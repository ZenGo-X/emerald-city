/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::traits::Hash;
use cryptoxide::digest::Digest;
use cryptoxide::sha2::Sha256;
use curv::arithmetic::num_bigint::{from, BigInt};
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};

pub struct HSha256;

impl Hash for HSha256 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut hasher = Sha256::new();

        for value in big_ints {
            let bytes: Vec<u8> = value.to_bytes_be();
            hasher.input(&bytes);
        }

        let mut result = [0; 32];
        hasher.result(&mut result);
        from(result.as_ref())
    }

    fn create_hash_from_ge(ge_vec: &[&GE]) -> FE {
        let mut hasher = Sha256::new();

        for value in ge_vec {
            let bytes = value.pk_to_key_slice();
            hasher.input(&bytes);
        }
        let mut result = [0; 32];
        hasher.result(&mut result);
        let result = from(result.as_ref());
        ECScalar::from(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::HSha256;
    use super::Hash;
    use curv::arithmetic::num_bigint::BigInt;
    use curv::elliptic::curves::secp256_k1::GE;
    use curv::elliptic::curves::traits::ECPoint;
    use curv::elliptic::curves::traits::ECScalar;
    use num_traits::{One, Zero};
    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_test() {
        HSha256::create_hash(&vec![]);

        let result = HSha256::create_hash(&vec![&BigInt::one(), &BigInt::zero()]);
        assert!(result > BigInt::zero());
    }

    #[test]
    fn create_hash_from_ge_test() {
        let point = GE::base_point2();
        let result1 = HSha256::create_hash_from_ge(&vec![&point, &GE::generator()]);
        assert!(result1.to_big_int().to_str_radix(2).len() > 240);
        let result2 = HSha256::create_hash_from_ge(&vec![&GE::generator(), &point]);
        assert_ne!(result1, result2);
        let result3 = HSha256::create_hash_from_ge(&vec![&GE::generator(), &point]);
        assert_eq!(result2, result3);
    }
}
