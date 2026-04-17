//! Precomputed prime tables and prime helpers.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SmallPrime {
    pub(crate) p: u32,
    pub(crate) g: u32,
    pub(crate) s: u32,
}

include!("primes_table.rs");

#[cfg(test)]
mod tests {
    use super::{SmallPrime, PRIMES2};

    #[test]
    fn primes2_shape_matches_reference() {
        assert_eq!(PRIMES2.len(), 522);
        assert_eq!(
            PRIMES2[0],
            SmallPrime {
                p: 2_147_473_409,
                g: 383_167_813,
                s: 10_239,
            }
        );
        assert_eq!(
            PRIMES2[520],
            SmallPrime {
                p: 2_135_955_457,
                g: 538_755_304,
                s: 1_688_831_340,
            }
        );
        assert_eq!(PRIMES2[521], SmallPrime { p: 0, g: 0, s: 0 });
    }
}
