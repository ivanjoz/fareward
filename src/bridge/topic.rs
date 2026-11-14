//! Topics: named fan-out groups of tabs. A tab subscribes when it opens its stream
//! (`GET /sse?ch=…&topics=a,b`) and the backend reaches every subscriber at once with
//! `POST /publish-topic`. A topic is `<name>.<companyID>[.<more>]`: the second segment names the
//! tenant whose events it carries, which is what lets the bridge refuse a tab subscribing to
//! another company's topic without knowing anything else about the name.

/// Bounds what one stream may ask for, so a client cannot grow the registry without limit.
pub const MAX_TOPICS_PER_STREAM: usize = 16;
pub const MAX_TOPIC_LENGTH: usize = 96;

/// The company a topic belongs to, or why the name is not a topic.
pub fn topic_company_id(topic: &str) -> Result<i32, String> {
    if topic.is_empty() || topic.len() > MAX_TOPIC_LENGTH {
        return Err(format!(
            "el tópico debe tener entre 1 y {MAX_TOPIC_LENGTH} caracteres"
        ));
    }
    if !topic
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(format!(
            "el tópico {topic:?} tiene caracteres no permitidos"
        ));
    }
    let mut segments = topic.split('.');
    let name = segments.next().unwrap_or_default();
    let company_segment = segments.next().unwrap_or_default();
    let company_id = company_segment
        .parse::<i32>()
        .ok()
        .filter(|_| !name.is_empty());
    company_id
        .filter(|company_id| *company_id > 0)
        .ok_or_else(|| format!("el tópico {topic:?} no es <nombre>.<empresa>[.…]"))
}

/// Parses a stream's `?topics=` (comma-separated) and refuses any topic of another company. An
/// empty value subscribes to nothing. Duplicates collapse.
pub fn parse_stream_topics(raw_topics: &str, company_id: i32) -> Result<Vec<String>, String> {
    let mut topics: Vec<String> = Vec::new();
    for topic in raw_topics
        .split(',')
        .map(str::trim)
        .filter(|topic| !topic.is_empty())
    {
        if topic_company_id(topic)? != company_id {
            return Err(format!(
                "el tópico {topic:?} no pertenece a la empresa del usuario"
            ));
        }
        if !topics.iter().any(|known| known == topic) {
            topics.push(topic.to_owned());
        }
    }
    if topics.len() > MAX_TOPICS_PER_STREAM {
        return Err(format!(
            "un stream admite hasta {MAX_TOPICS_PER_STREAM} tópicos"
        ));
    }
    Ok(topics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_topic_names_its_company_in_the_second_segment() {
        assert_eq!(topic_company_id("dining.7.3"), Ok(7));
        assert_eq!(topic_company_id("dining.7"), Ok(7));
        for invalid in [
            "",
            "dining",
            "dining.",
            ".7",
            "dining.x.3",
            "dining.0",
            "dining.-2",
            "dining.7.a b",
            "dining.7/3",
        ] {
            assert!(
                topic_company_id(invalid).is_err(),
                "{invalid:?} must be refused"
            );
        }
        assert!(topic_company_id(&format!("dining.7.{}", "a".repeat(MAX_TOPIC_LENGTH))).is_err());
    }

    #[test]
    fn a_stream_only_subscribes_to_its_own_company() {
        assert_eq!(
            parse_stream_topics(" dining.7.3, dining.7.4,dining.7.3,", 7),
            Ok(vec!["dining.7.3".to_owned(), "dining.7.4".to_owned()])
        );
        assert_eq!(parse_stream_topics("", 7), Ok(vec![]));
        assert!(parse_stream_topics("dining.7.3,dining.8.3", 7).is_err());
    }

    #[test]
    fn a_stream_has_a_topic_budget() {
        let topics: Vec<String> = (0..=MAX_TOPICS_PER_STREAM)
            .map(|index| format!("dining.7.{index}"))
            .collect();
        assert!(parse_stream_topics(&topics.join(","), 7).is_err());
        assert!(parse_stream_topics(&topics[..MAX_TOPICS_PER_STREAM].join(","), 7).is_ok());
    }
}
