//! The §23 normalizer — a port of `packages/policy/src/engine.ts:68-85`.
//!
//! The TS runs four passes over the string (NFKC + lowercase, zero-width strip,
//! leetspeak fold, punctuation/whitespace collapse + trim). This runs the first
//! pass, then fuses the other three into one character walk. The fusion is
//! behaviour-preserving, and each step below says why.

use unicode_normalization::UnicodeNormalization;
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

/// The exact code points in the character class at `engine.ts:71`, which is
/// written with literal (invisible) characters in the source. Decoded from the
/// UTF-8 bytes of that line rather than guessed:
///
/// ```text
/// 2f 5b e2 80 8b 2d e2 80 8f e2 81 a0 ef bb bf 5d 2f 67
///  /  [  <U+200B>  -  <U+200F>  <U+2060>  <U+FEFF>  ]  /  g
/// ```
///
/// i.e. the range U+200B..=U+200F, plus U+2060 and U+FEFF.
const ZERO_WIDTH: [char; 7] = [
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{200E}', // LEFT-TO-RIGHT MARK
    '\u{200F}', // RIGHT-TO-LEFT MARK
    '\u{2060}', // WORD JOINER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE (BOM)
];

fn is_zero_width(c: char) -> bool {
    ZERO_WIDTH.contains(&c)
}

/// engine.ts:73-81, in the TS's own order. The TS applies these as eight
/// sequential global replaces; doing them in one pass is byte-identical because
/// no replacement's output ('a', 's', 'o', 'i', 'e', 't') is itself a key, so no
/// later pass can ever see a character an earlier pass produced.
fn fold_leet(c: char) -> char {
    match c {
        '@' => 'a',
        '$' => 's',
        '0' => 'o',
        '1' => 'i',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        _ => c,
    }
}

/// ECMAScript `\s` — *not* Rust's `char::is_whitespace`. The two differ in both
/// directions, and both differences are load-bearing here:
///
/// * **U+0085 (NEL)** has Unicode `White_Space=Yes`, so `char::is_whitespace`
///   returns true, but it is neither ECMAScript `WhiteSpace` nor
///   `LineTerminator`, so JS `\s` does not match it. JS therefore leaves a NEL
///   in the text as an ordinary character (it is `Cc`, so `\p{P}`/`\p{S}` do not
///   catch it either) and `String.prototype.trim` will not strip it. So neither
///   may we — hence the explicit exclusion, and hence the hand-rolled trim in
///   `normalize` instead of `str::trim`.
/// * **U+FEFF** is the mirror case: ECMAScript `WhiteSpace` includes it, Rust's
///   `White_Space` property does not. It is unreachable here only because
///   `ZERO_WIDTH` strips it first. It is spelled out anyway so that shortening
///   the strip set does not silently change this line's meaning.
fn is_js_whitespace(c: char) -> bool {
    c == '\u{FEFF}' || (c.is_whitespace() && c != '\u{0085}')
}

/// The `[\s\p{P}\p{S}]` class at engine.ts:83. `\p{P}` and `\p{S}` are the
/// General_Category *groups* Punctuation (Pc/Pd/Ps/Pe/Pi/Pf/Po) and Symbol
/// (Sm/Sc/Sk/So), which is exactly what `general_category_group()` reports.
fn is_collapsible(c: char) -> bool {
    is_js_whitespace(c)
        || matches!(
            c.general_category_group(),
            GeneralCategoryGroup::Punctuation | GeneralCategoryGroup::Symbol
        )
}

/// §23: NFKC compatibility fold, lowercase, strip zero-width, fold leetspeak,
/// collapse punctuation/whitespace. See `engine.ts:61-85` for why NFKC and not
/// NFC (request canonicalization is the separate, NFC step).
pub fn normalize(text: &str) -> String {
    // engine.ts:69 — NFKC first, then lowercase, in that order.
    //
    // `str::to_lowercase` and JS `toLowerCase` both implement full (non-Turkic)
    // Unicode lowercasing including the Final_Sigma rule, but they are two
    // independent implementations pinned to two different Unicode versions.
    // Any divergence is for the differential harness to surface; do not paper
    // over one here.
    let folded: String = text.nfkc().collect::<String>().to_lowercase();

    let mut out = String::with_capacity(folded.len());
    // A run of collapsible characters becomes a single U+0020 — but only once
    // some output exists, and only if more output follows. That is precisely
    // `.replace(/[\s\p{P}\p{S}]+/gu, " ").trim()`: a leading run would produce a
    // leading space that `trim` then removes, and a trailing run likewise.
    let mut pending_space = false;

    for c in folded.chars() {
        // Zero-width strip runs before the collapse, exactly as in the TS, so a
        // zero-width character sitting inside a run of spaces does not split
        // that run into two.
        if is_zero_width(c) {
            continue;
        }
        // ...and the leet fold runs before the collapse too, which is what
        // keeps '@' and '$' (Po and Sc respectively) from being eaten as
        // punctuation instead of becoming letters.
        let c = fold_leet(c);
        if is_collapsible(c) {
            pending_space = true;
            continue;
        }
        if pending_space {
            if !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
        }
        out.push(c);
    }

    out
}
