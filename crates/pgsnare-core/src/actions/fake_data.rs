// SPDX-License-Identifier: Apache-2.0

//! `fake_data`: made-up rows at the end of a result the client reads.
//!
//! The rows are built from the result itself. While the server sends a
//! result whose `RowDescription` the session has seen, [`FakeRows`] keeps
//! a bounded sample of the values of each column, taken only from rows in
//! which nothing was found. When a hit asks for fake data, the rows are
//! added just before the `CommandComplete` of the result, and its row count
//! is raised by the number added.
//!
//! Each made-up row takes, for each column:
//!
//! - in a text column whose name says it holds a password or hash, a key,
//!   token or secret, a card number or an account name: generated bait of
//!   that kind, if it fits the declared length;
//! - in a text column whose name says it holds an email address: a
//!   generated account name at the domain of a sampled address;
//! - in a `uuid` column: a new random version 4 UUID;
//! - in an integer column named `id`: the next number above every `id` of
//!   the result, so no row repeats one;
//! - in any other column: one of the sampled values, drawn at random.
//!
//! Rows are not added, and the result goes on as the server sent it, when
//! a column is in binary format, a column has no sample to draw from, the
//! command is not a `SELECT`, the random source fails, or the rows built
//! contain anything the matcher finds. The caller decides before the hit
//! is reported whether rows can be added at all (see the inspector), so
//! these cases are rare.

use core::fmt::Write as _;

use pgsnare_proto::backend::{CommandComplete, DataRow, RowDescription};
use pgsnare_proto::{Frame, encode};

use crate::bait::{self, Entropy, Kind};
use crate::detect::Matcher;

/// The most columns of a result that rows are made up for.
pub const MAX_COLUMNS: usize = 256;
/// The most values kept of each column.
pub const MAX_SAMPLES: usize = 32;
/// The longest value kept.
pub const MAX_FIELD_BYTES: usize = 1024;
/// The most bytes kept for one result, over all its columns.
pub const MAX_SAMPLE_BYTES: usize = 64 * 1024;
/// The most bytes of made-up rows added to one result. Fewer rows than
/// the settings ask for are added when they would take more.
pub const MAX_ADDED_BYTES: usize = 8 * 1024 * 1024;

const TEXT_TYPES: [u32; 4] = [25, 1043, 1042, 19];
const INTEGER_TYPES: [u32; 3] = [20, 21, 23];
const UUID_TYPE: u32 = 2950;

/// How a column of a made-up row is filled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fill {
    Sampled,
    Bait(BaitKind),
    Email,
    Uuid,
    NextId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BaitKind {
    Password,
    Key,
    Card,
    Account,
}

impl BaitKind {
    const fn kind(self) -> Kind<'static> {
        match self {
            Self::Password => Kind::Bcrypt,
            Self::Key => Kind::ApiKey,
            Self::Card => Kind::CardNumber,
            Self::Account => Kind::AccountName,
        }
    }
}

fn fill_of(name: &[u8], type_oid: u32) -> Fill {
    let name = name.to_ascii_lowercase();
    let has = |part: &str| name.windows(part.len()).any(|w| w == part.as_bytes());
    if TEXT_TYPES.contains(&type_oid) {
        if has("password") || has("passwd") || has("pwd") || has("hash") {
            return Fill::Bait(BaitKind::Password);
        }
        if has("api_key") || has("apikey") || has("token") || has("secret") {
            return Fill::Bait(BaitKind::Key);
        }
        if has("card") {
            return Fill::Bait(BaitKind::Card);
        }
        if has("email") {
            return Fill::Email;
        }
        if matches!(
            name.as_slice(),
            b"username" | b"user_name" | b"login" | b"account" | b"account_name"
        ) {
            return Fill::Bait(BaitKind::Account);
        }
    }
    if type_oid == UUID_TYPE {
        return Fill::Uuid;
    }
    if INTEGER_TYPES.contains(&type_oid) && name == b"id" {
        return Fill::NextId;
    }
    Fill::Sampled
}

struct Column {
    fill: Fill,
    /// The longest text the column takes, when it declares one.
    max_chars: Option<usize>,
    samples: Vec<Option<Vec<u8>>>,
    /// The highest `id` of the result, for [`Fill::NextId`].
    highest: Option<i64>,
}

/// A result the session follows, and what it keeps of it.
pub struct FakeRows {
    columns: Vec<Column>,
    sampled_bytes: usize,
    /// Whether a row did not match the description; rows are then not
    /// added.
    broken: bool,
    chosen: bool,
}

impl core::fmt::Debug for FakeRows {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeRows")
            .field("columns", &self.columns.len())
            .field("sampled_bytes", &self.sampled_bytes)
            .field("chosen", &self.chosen)
            .finish_non_exhaustive()
    }
}

impl FakeRows {
    /// Follows the result a `RowDescription` announces. `None` when rows
    /// cannot be made up for it: a column in binary format, no column,
    /// too many, or a message that does not parse.
    #[must_use]
    pub fn describe(frame: Frame<'_>) -> Option<Self> {
        let description = RowDescription::from_frame(frame).ok()?;
        if description.is_empty() || description.len() > MAX_COLUMNS {
            return None;
        }
        let mut columns = Vec::with_capacity(description.len());
        for field in description.iter() {
            if !field.format().is_text() {
                return None;
            }
            let max_chars = usize::try_from(field.type_modifier())
                .ok()
                .and_then(|modifier| modifier.checked_sub(4))
                .filter(|_| TEXT_TYPES.contains(&field.type_oid()));
            columns.push(Column {
                fill: fill_of(field.name(), field.type_oid()),
                max_chars,
                samples: Vec::new(),
                highest: None,
            });
        }
        Some(Self {
            columns,
            sampled_bytes: 0,
            broken: false,
            chosen: false,
        })
    }

    /// Rows are to be added to this result.
    pub const fn choose(&mut self) {
        self.chosen = true;
    }

    /// Whether rows are to be added to this result.
    #[must_use]
    pub const fn is_chosen(&self) -> bool {
        self.chosen
    }

    /// Takes note of a `DataRow` of the result. Its values are kept only
    /// when `clean`, that is when nothing was found in the row.
    pub fn observe(&mut self, frame: Frame<'_>, clean: bool) {
        let Ok(row) = DataRow::from_frame(frame) else {
            self.broken = true;
            return;
        };
        if row.len() != self.columns.len() {
            self.broken = true;
            return;
        }
        for (column, value) in self.columns.iter_mut().zip(row) {
            if column.fill == Fill::NextId {
                let number = value
                    .and_then(|bytes| core::str::from_utf8(bytes).ok())
                    .and_then(|text| text.parse::<i64>().ok());
                match number {
                    Some(number) => {
                        column.highest = Some(column.highest.map_or(number, |h| h.max(number)));
                    }
                    // Without every id known, a new one could repeat one.
                    None => self.broken = true,
                }
            }
            let size = value.map_or(0, <[u8]>::len);
            if !clean
                || column.samples.len() >= MAX_SAMPLES
                || size > MAX_FIELD_BYTES
                || self.sampled_bytes.saturating_add(size) > MAX_SAMPLE_BYTES
            {
                continue;
            }
            self.sampled_bytes = self.sampled_bytes.saturating_add(size);
            column.samples.push(value.map(<[u8]>::to_vec));
        }
    }

    /// Writes up to `rows` made-up rows and the `CommandComplete` in place
    /// of `complete` to `out`, and returns how many rows were added. On
    /// `None` nothing was written, and `complete` is to go on unchanged.
    pub fn finish(
        &self,
        rows: u32,
        complete: Frame<'_>,
        matcher: &Matcher,
        entropy: &mut dyn Entropy,
        out: &mut Vec<u8>,
    ) -> Option<u64> {
        if !self.chosen || self.broken {
            return None;
        }
        let complete = CommandComplete::from_frame(complete).ok()?;
        let (command, count) = complete.split_rows()?;
        if command != b"SELECT" {
            return None;
        }
        let mut added: Vec<u8> = Vec::new();
        let mut made: u64 = 0;
        for number in 1..=rows {
            let row = self.row(i64::from(number), entropy)?;
            let values: Vec<Option<&[u8]>> = row.iter().map(|v| v.as_deref()).collect();
            let mut encoded = Vec::new();
            encode::data_row(&values, &mut encoded).ok()?;
            if added.len().saturating_add(encoded.len()) > MAX_ADDED_BYTES {
                break;
            }
            added.extend_from_slice(&encoded);
            made = made.saturating_add(1);
        }
        if made == 0 || matcher.scan(&added).next().is_some() {
            return None;
        }
        let total = count.checked_add(made)?;
        let mut tail = Vec::new();
        encode::command_complete_with_rows(command, total, &mut tail).ok()?;
        out.extend_from_slice(&added);
        out.extend_from_slice(&tail);
        Some(made)
    }

    /// One made-up row, the `number`-th.
    fn row(&self, number: i64, entropy: &mut dyn Entropy) -> Option<Vec<Option<Vec<u8>>>> {
        let mut row = Vec::with_capacity(self.columns.len());
        for column in &self.columns {
            let value = match column.fill {
                Fill::Sampled => pick(&column.samples, entropy)?,
                Fill::Bait(kind) => {
                    let bait = bait::generate(kind.kind(), entropy).ok()?;
                    let text = bait.expose().as_bytes().to_vec();
                    if column.max_chars.is_some_and(|max| text.len() > max) {
                        pick(&column.samples, entropy)?
                    } else {
                        Some(text)
                    }
                }
                Fill::Email => email(column, entropy)?,
                Fill::Uuid => Some(uuid(entropy)?),
                Fill::NextId => {
                    let next = column.highest?.checked_add(number)?;
                    Some(next.to_string().into_bytes())
                }
            };
            row.push(value);
        }
        Some(row)
    }
}

fn draw(entropy: &mut dyn Entropy, below: usize) -> Option<usize> {
    let mut bytes = [0u8; 8];
    entropy.fill(&mut bytes).ok()?;
    let below = u64::try_from(below).ok()?;
    let drawn = u64::from_le_bytes(bytes).checked_rem(below)?;
    usize::try_from(drawn).ok()
}

fn pick(samples: &[Option<Vec<u8>>], entropy: &mut dyn Entropy) -> Option<Option<Vec<u8>>> {
    let index = draw(entropy, samples.len())?;
    samples.get(index).cloned()
}

/// A generated account at the domain of a sampled address.
fn email(column: &Column, entropy: &mut dyn Entropy) -> Option<Option<Vec<u8>>> {
    let domains: Vec<&[u8]> = column
        .samples
        .iter()
        .flatten()
        .filter_map(|value| {
            let at = value.iter().rposition(|byte| *byte == b'@')?;
            value.get(at.checked_add(1)?..).filter(|d| !d.is_empty())
        })
        .collect();
    let domain = domains.get(draw(entropy, domains.len())?)?;
    let account = bait::generate(Kind::AccountName, entropy).ok()?;
    let mut value = account.expose().as_bytes().to_vec();
    value.push(b'@');
    value.extend_from_slice(domain);
    if column.max_chars.is_some_and(|max| value.len() > max) {
        return None;
    }
    Some(Some(value))
}

fn uuid(entropy: &mut dyn Entropy) -> Option<Vec<u8>> {
    let mut bytes = [0u8; 16];
    entropy.fill(&mut bytes).ok()?;
    if let Some(version) = bytes.get_mut(6) {
        *version = (*version & 0x0f) | 0x40;
    }
    if let Some(variant) = bytes.get_mut(8) {
        *variant = (*variant & 0x3f) | 0x80;
    }
    let mut text = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        let _ = write!(text, "{byte:02x}");
    }
    Some(text.into_bytes())
}
