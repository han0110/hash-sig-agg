pub mod engine;
pub mod field;

/// A generic trait for types that can be borrowed from a `[T]` slice.
pub trait AlignBorrow<T>: Sized {
    /// The expected size for this type.
    const SIZE: usize;

    /// Aligns and borrows a reference.
    fn align_borrow(slice: &[T]) -> &Self {
        debug_assert_eq!(slice.len(), Self::SIZE);
        let (prefix, shorts, suffix) = unsafe { slice.align_to::<Self>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }

    /// Aligns and borrows a mutable reference.
    fn align_borrow_mut(slice: &mut [T]) -> &mut Self {
        debug_assert_eq!(slice.len(), Self::SIZE);
        let (prefix, shorts, suffix) = unsafe { slice.align_to_mut::<Self>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

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
