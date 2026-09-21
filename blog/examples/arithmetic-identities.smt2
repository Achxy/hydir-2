(set-logic QF_BV)
(declare-fun a () (_ BitVec 64))
(declare-fun b () (_ BitVec 64))
(define-fun sign ((x (_ BitVec 64))) Bool (= ((_ extract 63 63) x) #b1))
(define-fun plus () (_ BitVec 64) (bvadd a b))
(define-fun minus () (_ BitVec 64) (bvsub a b))

; addition carry
(push 1)
(assert (not (= (bvult plus a) (= ((_ extract 64 64) (bvadd ((_ zero_extend 1) a) ((_ zero_extend 1) b))) #b1))))
(check-sat)
(pop 1)

; addition overflow
(push 1)
(assert (not (= (and (= (sign a) (sign b)) (xor (sign a) (sign plus))) (not (= ((_ sign_extend 1) plus) (bvadd ((_ sign_extend 1) a) ((_ sign_extend 1) b)))))))
(check-sat)
(pop 1)

; subtraction borrow
(push 1)
(assert (not (= (bvult a b) (= ((_ extract 64 64) (bvsub ((_ zero_extend 1) a) ((_ zero_extend 1) b))) #b1))))
(check-sat)
(pop 1)

; subtraction overflow
(push 1)
(assert (not (= (and (xor (sign a) (sign b)) (xor (sign a) (sign minus))) (not (= ((_ sign_extend 1) minus) (bvsub ((_ sign_extend 1) a) ((_ sign_extend 1) b)))))))
(check-sat)
(pop 1)

; signed comparison
(push 1)
(assert (not (= (xor (sign minus) (and (xor (sign a) (sign b)) (xor (sign a) (sign minus)))) (bvslt a b))))
(check-sat)
(pop 1)

; sign-bit bias ordering
(push 1)
(assert (not (= (bvslt a b) (bvult (bvxor a #x8000000000000000) (bvxor b #x8000000000000000)))))
(check-sat)
(pop 1)
