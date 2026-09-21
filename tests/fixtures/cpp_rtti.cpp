class HydirBase {
public:
    virtual long apply(long value) const = 0;
    virtual ~HydirBase();
};

HydirBase::~HydirBase() = default;

class HydirDerived final : public HydirBase {
public:
    explicit HydirDerived(long bias) : bias_(bias) {}

    long apply(long value) const override { return value * 3 + bias_; }

private:
    long bias_;
};

extern "C" __attribute__((noinline)) long hydir_cpp_dispatch(
    const HydirBase *instance,
    long value) {
    return instance->apply(value);
}

extern "C" __attribute__((noinline)) long hydir_cpp_local(long value) {
    HydirDerived instance(7);
    return instance.apply(value);
}
