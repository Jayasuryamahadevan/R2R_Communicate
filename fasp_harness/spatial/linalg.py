"""Small dense linear algebra, in pure Python, for pose uncertainty.

This harness has no numeric dependency and should not acquire one: it runs
on industrial edge hardware where every wheel is a supply-chain question
(`fasp_harness/security/`). The matrices here are 3x3 rotations and 6x6
pose covariances -- small enough that a readable implementation is also a
fast enough one.

Scope is deliberately narrow: the symmetric positive-semidefinite case that
covariance actually is, and the 3x3 SVD that Kabsch/Umeyama frame alignment
actually needs. There is no general eigensolver, because a general
eigensolver would invite callers to use it on matrices whose conditioning
this module makes no promises about.

The numerical property callers depend on: `jacobi_eigh` is the cyclic
Jacobi method, which for symmetric matrices converges unconditionally and
resolves small eigenvalues to high *relative* accuracy. That matters
because a near-degenerate covariance -- a robot confident along a corridor
and uncertain across it -- is the normal case here, not the pathological
one, and a solver that returns a small negative eigenvalue for it turns a
guard-band radius into a NaN at exactly the moment the guard band is the
thing keeping two machines apart.
"""

from __future__ import annotations

import math

Matrix = list[list[float]]
Vector = list[float]

__all__ = [
    "Matrix",
    "Vector",
    "conservative_sum",
    "identity",
    "transpose",
    "matmul",
    "matvec",
    "mat_add",
    "mat_sub",
    "mat_scale",
    "outer",
    "symmetrize",
    "det3",
    "trace",
    "jacobi_eigh",
    "max_eigenvalue",
    "svd3",
    "cholesky",
    "nearest_psd",
    "is_symmetric",
    "quadratic_form",
    "inverse",
    "NotPositiveSemidefinite",
]


class NotPositiveSemidefinite(ValueError):
    """A matrix offered as a covariance is not one.

    Raised rather than silently repaired. A caller that wants repair asks
    for it by name via `nearest_psd`, so the repair appears in the code
    that chose it instead of hiding inside a constructor.
    """


def identity(size: int) -> Matrix:
    return [[1.0 if row == column else 0.0 for column in range(size)] for row in range(size)]


def transpose(matrix: Matrix) -> Matrix:
    return [list(column) for column in zip(*matrix, strict=True)]


def matmul(left: Matrix, right: Matrix) -> Matrix:
    if len(left[0]) != len(right):
        raise ValueError("Matrix shapes do not compose.")
    right_columns = list(zip(*right, strict=True))
    return [[math.fsum(a * b for a, b in zip(row, column, strict=True)) for column in right_columns] for row in left]


def matvec(matrix: Matrix, vector: Vector) -> Vector:
    if len(matrix[0]) != len(vector):
        raise ValueError("Matrix and vector shapes do not compose.")
    return [math.fsum(a * b for a, b in zip(row, vector, strict=True)) for row in matrix]


def mat_add(left: Matrix, right: Matrix) -> Matrix:
    return [[a + b for a, b in zip(x, y, strict=True)] for x, y in zip(left, right, strict=True)]


def mat_sub(left: Matrix, right: Matrix) -> Matrix:
    return [[a - b for a, b in zip(x, y, strict=True)] for x, y in zip(left, right, strict=True)]


def mat_scale(matrix: Matrix, factor: float) -> Matrix:
    return [[value * factor for value in row] for row in matrix]


def outer(left: Vector, right: Vector) -> Matrix:
    return [[a * b for b in right] for a in left]


def symmetrize(matrix: Matrix) -> Matrix:
    """Average a matrix with its transpose.

    Repeated `F P F' + Q` propagation accumulates asymmetry in the last
    bits, and an eigensolver handed a matrix that is symmetric to only 15
    digits is being asked a question it was not designed for. Cheap to fix
    at every step; expensive to diagnose once it has drifted.
    """
    size = len(matrix)
    return [[0.5 * (matrix[row][column] + matrix[column][row]) for column in range(size)] for row in range(size)]


def trace(matrix: Matrix) -> float:
    return math.fsum(matrix[index][index] for index in range(len(matrix)))


def det3(matrix: Matrix) -> float:
    (a, b, c), (d, e, f), (g, h, i) = matrix
    return a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)


def is_symmetric(matrix: Matrix, tolerance: float = 1e-9) -> bool:
    size = len(matrix)
    if any(len(row) != size for row in matrix):
        return False
    scale = max((abs(value) for row in matrix for value in row), default=0.0)
    bound = tolerance * max(scale, 1.0)
    return all(abs(matrix[row][column] - matrix[column][row]) <= bound for row in range(size) for column in range(row + 1, size))


def jacobi_eigh(matrix: Matrix, max_sweeps: int = 64, tolerance: float = 1e-14) -> tuple[Vector, Matrix]:
    """Eigendecomposition of a symmetric matrix by cyclic Jacobi rotations.

    Returns `(eigenvalues, eigenvectors)` with eigenvalues in descending
    order and eigenvectors as the *columns* of the returned matrix, so
    `A == V diag(w) V'`.

    Cyclic Jacobi is chosen over anything faster because it converges for
    every symmetric input without a shift strategy to get wrong, and
    because it is short enough to audit. For 6x6 covariance the cost is
    irrelevant next to the SQLite write that follows it.
    """
    if not is_symmetric(matrix):
        raise ValueError("jacobi_eigh requires a symmetric matrix.")
    size = len(matrix)
    if size == 0:
        return [], []
    working = [list(row) for row in matrix]
    vectors = identity(size)

    for _ in range(max_sweeps):
        off_diagonal = math.sqrt(math.fsum(working[row][column] ** 2 for row in range(size) for column in range(size) if row != column))
        if off_diagonal <= tolerance * max(1.0, math.sqrt(math.fsum(working[i][i] ** 2 for i in range(size)))):
            break
        for p in range(size - 1):
            for q in range(p + 1, size):
                apq = working[p][q]
                if abs(apq) <= 1e-300:
                    continue
                # The standard stable rotation: solve for tan(theta) via the
                # root of smaller magnitude, which keeps the rotation close
                # to identity and avoids cancellation when app ~ aqq.
                theta = (working[q][q] - working[p][p]) / (2.0 * apq)
                sign = 1.0 if theta >= 0.0 else -1.0
                tangent = sign / (abs(theta) + math.sqrt(theta * theta + 1.0))
                cosine = 1.0 / math.sqrt(tangent * tangent + 1.0)
                sine = tangent * cosine

                for k in range(size):
                    akp, akq = working[k][p], working[k][q]
                    working[k][p] = cosine * akp - sine * akq
                    working[k][q] = sine * akp + cosine * akq
                for k in range(size):
                    apk, aqk = working[p][k], working[q][k]
                    working[p][k] = cosine * apk - sine * aqk
                    working[q][k] = sine * apk + cosine * aqk
                for k in range(size):
                    vkp, vkq = vectors[k][p], vectors[k][q]
                    vectors[k][p] = cosine * vkp - sine * vkq
                    vectors[k][q] = sine * vkp + cosine * vkq

    eigenvalues = [working[index][index] for index in range(size)]
    order = sorted(range(size), key=lambda index: eigenvalues[index], reverse=True)
    sorted_values = [eigenvalues[index] for index in order]
    sorted_vectors = [[vectors[row][index] for index in order] for row in range(size)]
    return sorted_values, sorted_vectors


def max_eigenvalue(matrix: Matrix) -> float:
    """Largest eigenvalue of a symmetric matrix, clamped at zero.

    This is the semi-axis a guard band is built from, so a tiny negative
    value produced by round-off must not reach `sqrt`. Clamping here is
    safe in the only direction that matters: it can shrink a radius by an
    amount smaller than floating-point noise, never grow one.
    """
    values, _ = jacobi_eigh(symmetrize(matrix))
    return max(values[0], 0.0) if values else 0.0


def svd3(matrix: Matrix) -> tuple[Matrix, Vector, Matrix]:
    """Singular value decomposition of a 3x3 matrix: `M == U diag(s) Vt`.

    Computed through the eigendecomposition of `M' M`. That route squares
    the condition number, which would be unacceptable for a general solver
    and is fine here: the only caller is Kabsch alignment, where `M` is a
    cross-covariance of mean-centred point sets and the answer feeds a
    rotation that is re-orthogonalised by construction anyway.

    Rank-deficient input -- every correspondence collinear, or all points
    coincident -- is handled rather than divided by. The returned `U` is
    completed to an orthonormal basis so the caller still gets a valid
    rotation instead of a NaN, and the near-zero singular values are the
    signal that lets `frames.py` refuse the fit.
    """
    if len(matrix) != 3 or any(len(row) != 3 for row in matrix):
        raise ValueError("svd3 requires a 3x3 matrix.")
    gram = symmetrize(matmul(transpose(matrix), matrix))
    eigenvalues, right = jacobi_eigh(gram)
    singular = [math.sqrt(max(value, 0.0)) for value in eigenvalues]

    right_columns = [[right[row][index] for row in range(3)] for index in range(3)]
    threshold = max(singular) * 1e-12 if singular and singular[0] > 0.0 else 0.0

    left_columns: list[Vector] = []
    for index in range(3):
        if singular[index] > threshold:
            column = matvec(matrix, right_columns[index])
            left_columns.append([value / singular[index] for value in column])
        else:
            left_columns.append([])

    # Complete any missing left-singular vectors into an orthonormal basis.
    for index in range(3):
        if left_columns[index]:
            continue
        left_columns[index] = _orthogonal_complement(left_columns, index)

    left = [[left_columns[column][row] for column in range(3)] for row in range(3)]
    right_transposed = transpose(right)
    return left, singular, right_transposed


def _orthogonal_complement(columns: list[Vector], index: int) -> Vector:
    """A unit vector orthogonal to every already-known column."""
    known = [column for position, column in enumerate(columns) if column and position != index]
    for candidate in ([1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]):
        vector = list(candidate)
        for basis in known:
            projection = math.fsum(a * b for a, b in zip(vector, basis, strict=True))
            vector = [value - projection * basis_value for value, basis_value in zip(vector, basis, strict=True)]
        norm = math.sqrt(math.fsum(value * value for value in vector))
        if norm > 1e-8:
            return [value / norm for value in vector]
    return [0.0, 0.0, 1.0]


def cholesky(matrix: Matrix, jitter: float = 0.0) -> Matrix:
    """Lower-triangular `L` with `L L' == A`, for symmetric positive-definite `A`.

    Doubles as the positive-definiteness test used when a covariance
    arrives over the wire: a peer can send any six-by-six array of floats,
    and `spatial/state.py` must reject one that is not a covariance before
    it is ever propagated. Failing here is the check.
    """
    size = len(matrix)
    if not is_symmetric(matrix):
        raise NotPositiveSemidefinite("Covariance must be symmetric.")
    lower = [[0.0] * size for _ in range(size)]
    for row in range(size):
        for column in range(row + 1):
            total = math.fsum(lower[row][k] * lower[column][k] for k in range(column))
            if row == column:
                pivot = matrix[row][row] + jitter - total
                if pivot <= 0.0:
                    raise NotPositiveSemidefinite(f"Covariance is not positive definite at index {row}.")
                lower[row][column] = math.sqrt(pivot)
            else:
                lower[row][column] = (matrix[row][column] - total) / lower[column][column]
    return lower


def nearest_psd(matrix: Matrix, floor: float = 0.0) -> Matrix:
    """Clamp negative eigenvalues to `floor`, rebuilding a valid covariance.

    Used after propagation, never on input. Accumulated round-off can drive
    a genuinely singular covariance -- a stationary robot, a perfectly
    constrained axis -- microscopically negative; refusing to coordinate
    because of that would be a self-inflicted outage. Repairing an
    *incoming* covariance would instead be laundering a peer's bad data
    into apparent validity, which is why `state.py` calls `cholesky`
    on receipt and this only on its own arithmetic.
    """
    values, vectors = jacobi_eigh(symmetrize(matrix))
    size = len(values)
    clamped = [max(value, floor) for value in values]
    scaled = [[vectors[row][column] * clamped[column] for column in range(size)] for row in range(size)]
    return symmetrize(matmul(scaled, transpose(vectors)))


def quadratic_form(vector: Vector, matrix: Matrix) -> float:
    """`v' A v`, the Mahalanobis numerator."""
    return math.fsum(a * b for a, b in zip(vector, matvec(matrix, vector), strict=True))


def inverse(matrix: Matrix) -> Matrix:
    """Gauss-Jordan inverse with partial pivoting."""
    size = len(matrix)
    augmented = [list(row) + identity(size)[index] for index, row in enumerate(matrix)]
    for column in range(size):
        pivot_row = max(range(column, size), key=lambda row: abs(augmented[row][column]))
        if abs(augmented[pivot_row][column]) < 1e-15:
            raise ValueError("Matrix is singular to working precision.")
        augmented[column], augmented[pivot_row] = augmented[pivot_row], augmented[column]
        pivot = augmented[column][column]
        augmented[column] = [value / pivot for value in augmented[column]]
        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            if factor == 0.0:
                continue
            augmented[row] = [value - factor * pivot_value for value, pivot_value in zip(augmented[row], augmented[column], strict=True)]
    return [row[size:] for row in augmented]


def conservative_sum(left: Matrix, right: Matrix, *, correlated: bool) -> Matrix:
    """Add two covariances, optionally without assuming they are independent.

    With `correlated=False` this is the ordinary `P_a + P_b`, valid only
    when the two error sources genuinely share nothing.

    With `correlated=True` it returns a bound that holds for *any*
    cross-covariance, which is what you need when two estimates might
    share a sensor and you cannot say how much. For any w in (0,1):

        Cov(A + B)  <=  (1/w) P_a + (1/(1-w)) P_b

    which follows from `0 <= Cov(aA - (1/a)B)` expanded and rearranged.
    Choosing w to minimise the trace has the closed form

        w = sqrt(tr P_a) / (sqrt(tr P_a) + sqrt(tr P_b))

    and gives a result whose trace is `(sqrt(tr P_a) + sqrt(tr P_b))^2` --
    that is, the standard deviations add *linearly* rather than in
    quadrature. Which is exactly right, and is the whole point: linear
    addition is what fully correlated errors do, and a bound that must
    cover the fully correlated case has to be able to reach it.

    The price is bounded and worth stating: for two equal covariances the
    result is twice the independent one, so sigma grows by sqrt(2). A 41%
    wider two-hop chain is a fair exchange for a bound that is not simply
    wrong whenever two frame links happen to share an anchor.

    This is the same reasoning as covariance intersection (Julier and
    Uhlmann, 1997), applied to a sum rather than to a fusion of two
    estimates of one quantity.
    """
    if not correlated:
        return symmetrize(mat_add(left, right))
    left_trace, right_trace = max(trace(left), 0.0), max(trace(right), 0.0)
    # A zero-trace covariance contributes nothing and would divide by zero.
    if left_trace <= 0.0:
        return symmetrize(right)
    if right_trace <= 0.0:
        return symmetrize(left)
    left_root, right_root = math.sqrt(left_trace), math.sqrt(right_trace)
    weight = left_root / (left_root + right_root)
    return symmetrize(mat_add(mat_scale(left, 1.0 / weight), mat_scale(right, 1.0 / (1.0 - weight))))
