// Example custom extern function.
extern void custom_set<T>(inout T a, in T b);

// Example custom extern object.
extern CustomCounter<T> {
    CustomCounter(T init_count);
    void reset();
    void read(out T count);
    void increment_by(in T amount);
}
