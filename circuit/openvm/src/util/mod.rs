pub mod engine;
pub mod field;

macro_rules! zip {
    (@closure $p:pat => $tup:expr) => {
        |$p| $tup
    };
    (@closure $p:pat => ($($tup:tt)*) , $_iter:expr $(, $tail:expr)*) => {
        $crate::util::zip!(@closure ($p, b) => ($($tup)*, b) $(, $tail)*)
    };
    ($first:expr $(,)*) => {
        ::core::iter::IntoIterator::into_iter($first)
    };
    ($first:expr, $second:expr $(,)*) => {{
        #[cfg(debug_assertions)]
        { ::itertools::Itertools::zip_eq($crate::util::zip!($first), $second) }
        #[cfg(not(debug_assertions))]
        { ::core::iter::Iterator::zip($crate::util::zip!($first), $second) }
    }};
    ($first:expr $(, $rest:expr)* $(,)*) => {{
        let t = $crate::util::zip!($first);
        $(let t = $crate::util::zip!(t, $rest);)*
        t.map($crate::util::zip!(@closure a => (a) $(, $rest)*))
    }};
}

macro_rules! par_zip {
    ($first:expr $(, $rest:expr)* $(,)*) => {{
        use p3_maybe_rayon::prelude::*;
        (($first $(, $rest)*)).into_par_iter()
    }};
}

pub(crate) use {hash_sig_verifier::concat_array, par_zip, zip};
