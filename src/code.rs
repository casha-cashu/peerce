use anyhow::Result;
use bip39::Language;
use rand::seq::SliceRandom;
use rand::thread_rng;

pub fn generate() -> String {
    let words = Language::English.word_list();
    let mut rng = thread_rng();
    let picked: Vec<&&str> = words.choose_multiple(&mut rng, 3).collect();
    format!("{}-{}-{}", picked[0], picked[1], picked[2])
}

pub fn normalize(input: &str) -> Result<String> {
    let parts: Vec<String> = input
        .split(['-', ' ', '_'])
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect();
    anyhow::ensure!(parts.len() == 3, "code must be 3 words");
    let words = Language::English.word_list();
    for w in &parts {
        anyhow::ensure!(words.contains(&w.as_str()), "unknown word: {w}");
    }
    Ok(parts.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_code_normalizes() {
        let c = generate();
        assert_eq!(c.split('-').count(), 3);
        assert_eq!(normalize(&c).unwrap(), c);
    }

    #[test]
    fn accepts_spaces_and_case() {
        let c = generate().replace('-', " ").to_uppercase();
        let n = normalize(&c).unwrap();
        assert_eq!(n.split('-').count(), 3);
    }

    #[test]
    fn rejects_two_words() {
        assert!(normalize("orbit-falcon").is_err());
    }

    #[test]
    fn rejects_unknown_word() {
        assert!(normalize("foo-bar-baz").is_err());
    }
}
