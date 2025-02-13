#[macro_export]
macro_rules! concat_array {
    [$first:expr $(, $rest:expr)* $(,)?] => {{
        let mut iter = $first.into_iter()$(.chain($rest))*;
        ::core::array::from_fn(|_| iter.next().unwrap_or_default())
    }};
}
