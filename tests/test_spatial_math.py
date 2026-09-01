"""The pure-Python linear algebra the spatial layer is built on.

These tests exist because everything downstream -- guard-band radii, frame
alignment, covariance propagation -- silently produces plausible-looking
numbers when the algebra underneath is subtly wrong. A rotation that is not
quite orthogonal still prints as a matrix; a covariance with a small
negative eigenvalue still serialises as JSON. So the properties are
asserted here, once, where a failure is unambiguous.
"""

from __future__ import annotations

import math
import unittest

from hypothesis import given, settings
from hypothesis import strategies as st

from fasp_harness.spatial.linalg import (
    NotPositiveSemidefinite,
    cholesky,
    det3,
    identity,
    inverse,
    jacobi_eigh,
    matmul,
    max_eigenvalue,
    nearest_psd,
    svd3,
    symmetrize,
    transpose,
)

finite = st.floats(min_value=-50.0, max_value=50.0, allow_nan=False, allow_infinity=False)


def _max_abs_difference(left: list[list[float]], right: list[list[float]]) -> float:
    return max(abs(a - b) for row_a, row_b in zip(left, right, strict=True) for a, b in zip(row_a, row_b, strict=True))


class JacobiEigenTests(unittest.TestCase):
    def test_reconstructs_the_original_matrix(self) -> None:
        matrix = [[4.0, 1.0, 0.2], [1.0, 3.0, 0.1], [0.2, 0.1, 1.0]]
        values, vectors = jacobi_eigh(matrix)
        diagonal = [[values[row] if row == column else 0.0 for column in range(3)] for row in range(3)]
        self.assertLess(_max_abs_difference(matmul(matmul(vectors, diagonal), transpose(vectors)), matrix), 1e-12)

    def test_eigenvectors_are_orthonormal(self) -> None:
        _, vectors = jacobi_eigh([[9.0, 2.0, 1.0], [2.0, 5.0, -1.0], [1.0, -1.0, 3.0]])
        self.assertLess(_max_abs_difference(matmul(transpose(vectors), vectors), identity(3)), 1e-12)

    def test_eigenvalues_come_back_in_descending_order(self) -> None:
        values, _ = jacobi_eigh([[1.0, 0.0, 0.0], [0.0, 7.0, 0.0], [0.0, 0.0, 3.0]])
        self.assertEqual([round(value, 9) for value in values], [7.0, 3.0, 1.0])

    def test_a_near_degenerate_covariance_keeps_a_non_negative_small_eigenvalue(self) -> None:
        """The corridor case: certain along one axis, uncertain across it.

        This is the normal shape of a real robot's covariance, and it is
        exactly where a careless solver returns a small negative number
        that becomes a NaN radius two layers up.
        """
        covariance = [[4.0, 0.0, 0.0], [0.0, 1e-14, 0.0], [0.0, 0.0, 1e-14]]
        values, _ = jacobi_eigh(covariance)
        self.assertTrue(all(value >= 0.0 for value in values), values)
        self.assertAlmostEqual(max_eigenvalue(covariance), 4.0, places=12)

    def test_rejects_an_asymmetric_matrix_instead_of_guessing(self) -> None:
        with self.assertRaises(ValueError):
            jacobi_eigh([[1.0, 2.0], [3.0, 4.0]])

    @settings(max_examples=60, deadline=None)
    @given(st.lists(st.lists(finite, min_size=3, max_size=3), min_size=3, max_size=3))
    def test_symmetric_reconstruction_holds_for_arbitrary_input(self, raw: list[list[float]]) -> None:
        matrix = symmetrize(raw)
        values, vectors = jacobi_eigh(matrix)
        diagonal = [[values[row] if row == column else 0.0 for column in range(3)] for row in range(3)]
        magnitude = max(1.0, max(abs(value) for row in matrix for value in row))
        self.assertLess(_max_abs_difference(matmul(matmul(vectors, diagonal), transpose(vectors)), matrix), 1e-9 * magnitude)


class Svd3Tests(unittest.TestCase):
    def test_reconstructs_a_full_rank_matrix(self) -> None:
        matrix = [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0], [7.0, 8.0, 10.0]]
        left, singular, right_transposed = svd3(matrix)
        diagonal = [[singular[row] if row == column else 0.0 for column in range(3)] for row in range(3)]
        self.assertLess(_max_abs_difference(matmul(matmul(left, diagonal), right_transposed), matrix), 1e-11)

    def test_singular_values_are_non_negative_and_descending(self) -> None:
        _, singular, _ = svd3([[0.0, -2.0, 0.0], [1.0, 0.0, 0.0], [0.0, 0.0, 0.5]])
        self.assertEqual([round(value, 9) for value in singular], [2.0, 1.0, 0.5])

    def test_rank_deficient_input_still_yields_an_orthonormal_basis(self) -> None:
        """Every correspondence collinear, or all points coincident.

        Real data does this -- a robot parked, or three markers in a row --
        and the caller needs a usable rotation plus a near-zero singular
        value it can refuse on, not a division by zero.
        """
        left, singular, right_transposed = svd3([[1.0, 0.0, 0.0], [0.0, 0.0, 0.0], [0.0, 0.0, 0.0]])
        self.assertLess(_max_abs_difference(matmul(transpose(left), left), identity(3)), 1e-12)
        self.assertLess(_max_abs_difference(matmul(right_transposed, transpose(right_transposed)), identity(3)), 1e-12)
        self.assertAlmostEqual(singular[1], 0.0, places=12)

    def test_the_all_zero_matrix_does_not_divide_by_zero(self) -> None:
        left, singular, _ = svd3([[0.0] * 3 for _ in range(3)])
        self.assertEqual([round(value, 12) for value in singular], [0.0, 0.0, 0.0])
        self.assertAlmostEqual(abs(det3(left)), 1.0, places=9)


class CovarianceGuardTests(unittest.TestCase):
    def test_cholesky_accepts_a_valid_covariance(self) -> None:
        covariance = [[2.0, 0.3], [0.3, 1.0]]
        lower = cholesky(covariance)
        self.assertLess(_max_abs_difference(matmul(lower, transpose(lower)), covariance), 1e-12)

    def test_cholesky_rejects_an_indefinite_matrix_offered_as_covariance(self) -> None:
        """A peer can put any nine floats on the wire. This is the check."""
        with self.assertRaises(NotPositiveSemidefinite):
            cholesky([[1.0, 2.0], [2.0, 1.0]])

    def test_cholesky_rejects_an_asymmetric_matrix(self) -> None:
        with self.assertRaises(NotPositiveSemidefinite):
            cholesky([[1.0, 0.5], [0.1, 1.0]])

    def test_nearest_psd_repairs_round_off_without_inflating_the_matrix(self) -> None:
        repaired = nearest_psd([[1.0, 0.0], [0.0, -1e-18]])
        values, _ = jacobi_eigh(repaired)
        self.assertTrue(all(value >= 0.0 for value in values))
        self.assertAlmostEqual(repaired[0][0], 1.0, places=12)

    def test_max_eigenvalue_never_returns_a_negative_number(self) -> None:
        self.assertGreaterEqual(max_eigenvalue([[-1e-20, 0.0], [0.0, -1e-20]]), 0.0)
        self.assertFalse(math.isnan(math.sqrt(max_eigenvalue([[-1e-20, 0.0], [0.0, -1e-20]]))))


class InverseTests(unittest.TestCase):
    def test_inverts_a_well_conditioned_matrix(self) -> None:
        matrix = [[4.0, 1.0, 0.2], [1.0, 3.0, 0.1], [0.2, 0.1, 1.0]]
        self.assertLess(_max_abs_difference(matmul(matrix, inverse(matrix)), identity(3)), 1e-12)

    def test_refuses_a_singular_matrix(self) -> None:
        with self.assertRaises(ValueError):
            inverse([[1.0, 2.0], [2.0, 4.0]])


if __name__ == "__main__":
    unittest.main()
