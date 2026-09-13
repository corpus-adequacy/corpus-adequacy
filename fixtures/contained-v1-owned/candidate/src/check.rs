pub fn check(value: i64, maximum: i64) -> (bool, &'static str, String) {
    if value < 0 {
        return (false, "negative", format!("value {value} is below zero"));
    }
    if value > maximum {
        return (
            false,
            "above-maximum",
            format!("value {value} exceeds maximum {maximum}"),
        );
    }
    if value == i64::MIN {
        return (false, "minimum-sentinel", "minimum sentinel".to_owned());
    }
    (true, "accepted", format!("value {value} is within the declared range"))
}

#[cfg(test)]
mod tests {
    use super::check;

    #[test]
    fn frozen_cases_cover_both_guards_and_the_boundary() {
        assert_eq!(check(5, 10).0, true);
        assert_eq!(check(10, 10).0, true);
        assert_eq!(check(-1, 10).1, "negative");
        assert_eq!(check(11, 10).1, "above-maximum");
    }
}
