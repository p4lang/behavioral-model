# Implementing Externs in PSA Switch
Externs in PSA Switch are different than those in Simple Switch. 
Simple Switch uses externs baked into the BMV2 model where as PSA Switch
uses externs specific to its own architecture. To understand what this
translates to in code, look at the counter used in 
[Simple Switch](https://github.com/p4lang/behavioral-model/tree/master/src/bm_sim)
and the one in 
[PSA Switch](https://github.com/p4lang/behavioral-model/tree/master/targets/psa_switch/externs).
The Simple Switch counter lives inside of `src/bm_sim` where as the 
counter for PSA Switch lives inside of the target specific directory.
This doc is meant to provide guidance for developers on how to develop
new externs in PSA Switch.

## Background Knowledge
For those who are familiar with the internals of BMV2 feel free
to skip this section. For those who are new/less familiar with how BMV2
operates, consider reading `P4Objects.cpp` as a starting point
as this is where externs will be created. From here you can also see
what the expected JSON for externs should be. Next, read the changes
in the following [commit](https://github.com/p4lang/behavioral-model/pull/767).
It details all the changes made to support the counter extern in PSA.
It will also be useful to understand on a high level how P4 Runtime
interacts with PSA Switch. Briefly skimming `runtime_CLI.py` will do.

## High-Level Process
The following process should be taken when developing new externs in
PSA Switch.

1. Provide support for emitting the extern in p4c. Currently, only
   counters declared in P4 are translated to JSON in the p4c for PSA
   Switch. 
   This [commit](https://github.com/p4lang/p4c/commit/6d97bcf42f034ca113fa7a654fa998a7e10cba17)
   is an example for how to emit an extern object to JSON, and
   this [commit](https://github.com/p4lang/p4c/commit/bd6f231f7e6f24164f5d5156e0fad7a0680f2fa2)
   is an example for how to emit extern methods to JSON.
   If the examples aren't clear, one can always refer back to the JSON
   spec defined 
   [here](https://github.com/p4lang/behavioral-model/blob/master/docs/JSON_format.md).
   As for internals of how to the compiler works, check out its docs
   [here](https://github.com/p4lang/p4c/tree/master/docs).
2. Create the extern type in PSA Switch. There are several important
   things to note.
   1. The extern type must sub-class `bm::ExternType`.
   2. The extern should live within the `bm::psa` namespace.
   3. You must register the newly created extern type to the
      extern factory used by BMV2 to create externs from JSON 
      using `BM_REGISTER_EXTERN_W_NAME`.
   4. You must also register any extern methods used by P4 using 
      `BM_REGISTER_EXTERN_W_NAME_METHOD`.
   5. Create an `import_yourExternNameHere` dummy method and call 
      it within `psa_switch.cpp`.
3. Provide P4 Runtime support if necessary. This means overriding 
   parts of the PSA Switch/P4 Runtime interface as necessary so 
   that P4 Runtime can configure/monitor the newly developed extern.

## Common Issues
Here is a list of all the bugs encountered during the development of
counters and might serve as a helpful resource for others.
* The extern can't be created.
  * Most likely a mis-match between the supplied and expected JSON format.
  * Did you remember to register the extern into the extern factory?
* The extern method is not being called inside of an action.
  * Did you remember to register the extern method? These must be done
    by the programmer.
* P4 Runtime can't interact with my extern.
  * Did you remember to override necessary method in the P4 Runtime
    interface?
* I created a new extern, added it to the Makefile but it isn't
  being linked.
  * Dont forget step 2.5 from above
* Everything in BMV2 looks good, but it seems that P4c is
  failing.
  * Supporting additional externs might have allowed previous tests
    marked as XFAIL to pass which will cause P4c to fail. Double
    check the test case that has failed and see if this was the
    issue.

Refer to [this](https://github.com/p4lang/behavioral-model/pull/767) 
as a complete example.
