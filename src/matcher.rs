use crate::config::Keyword;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::Result;

/// Two Aho-Corasick automatons: one for case-sensitive, one for case-insensitive.
/// Each pattern's index maps back to the original `Keyword` via the lookup tables.
pub struct Matcher {
    pub case_sensitive_ac: Option<AhoCorasick>,
    pub case_insensitive_ac: Option<AhoCorasick>,
    pub cs_keywords: Vec<Keyword>,
    pub ci_keywords: Vec<Keyword>,
}

impl Matcher {
    pub fn build(keywords: &[Keyword]) -> Result<Self> {
        let mut cs_keywords = Vec::new();
        let mut ci_keywords = Vec::new();
        for kw in keywords {
            if kw.case_sensitive {
                cs_keywords.push(kw.clone());
            } else {
                ci_keywords.push(kw.clone());
            }
        }
        let cs_patterns: Vec<&str> = cs_keywords.iter().map(|k| k.pattern.as_str()).collect();
        let ci_patterns: Vec<&str> = ci_keywords.iter().map(|k| k.pattern.as_str()).collect();

        // Standard match kind is required for find_overlapping_iter, which we need
        // because multiple keywords can match the same span of text.
        let case_sensitive_ac = if !cs_patterns.is_empty() {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::Standard)
                    .ascii_case_insensitive(false)
                    .build(&cs_patterns)?,
            )
        } else {
            None
        };
        let case_insensitive_ac = if !ci_patterns.is_empty() {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::Standard)
                    .ascii_case_insensitive(true)
                    .build(&ci_patterns)?,
            )
        } else {
            None
        };

        Ok(Matcher {
            case_sensitive_ac,
            case_insensitive_ac,
            cs_keywords,
            ci_keywords,
        })
    }

    /// Find all matches in `haystack`. Returns (byte_offset, match_length, &Keyword).
    pub fn find_all<'a>(&'a self, haystack: &str) -> Vec<RawHit<'a>> {
        let mut hits = Vec::new();
        if let Some(ac) = &self.case_sensitive_ac {
            for m in ac.find_overlapping_iter(haystack) {
                hits.push(RawHit {
                    start: m.start(),
                    end: m.end(),
                    keyword: &self.cs_keywords[m.pattern().as_usize()],
                });
            }
        }
        if let Some(ac) = &self.case_insensitive_ac {
            for m in ac.find_overlapping_iter(haystack) {
                hits.push(RawHit {
                    start: m.start(),
                    end: m.end(),
                    keyword: &self.ci_keywords[m.pattern().as_usize()],
                });
            }
        }
        hits
    }
}

pub struct RawHit<'a> {
    pub start: usize,
    pub end: usize,
    pub keyword: &'a Keyword,
}
