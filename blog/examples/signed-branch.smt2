; A standalone algebraic check, not a proof of the HydIR implementation.
; Expected result: unsat.
(set-logic QF_BV)
(declare-fun a () (_ BitVec 64))
(declare-fun b () (_ BitVec 64))
(define-fun r () (_ BitVec 64) (bvsub a b))
(define-fun sign ((x (_ BitVec 64))) Bool
  (= ((_ extract 63 63) x) #b1))
(define-fun overflow () Bool
  (and (xor (sign a) (sign b))
       (xor (sign a) (sign r))))
(assert
  (not (= (xor (sign r) overflow) (bvslt a b))))
(check-sat)
