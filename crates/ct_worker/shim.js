import shim, {
    Sequencer, Batcher, Cleaner, __wbg_reset_state,
} from "./build/worker/shim.mjs";

// no-op worker entrypoint for now
const WorkerEntrypointProxy = new Proxy(shim, {});

const DOProxy = new Proxy(Sequencer, {
    construct(target, args) {
        const state = args[0] // get state
        // const env = args[1] // get env
        try {
            const instance = new target(...args);

            return new Proxy(instance, {
                get(target, prop, receiver) {
                    const original = Reflect.get(target, prop, receiver);
                    // Check if the property is a function
                    if (typeof original === 'function') {
                        return new Proxy(original, {
                            async apply(target, thisArg, argArray) {
                                try {
                                    const resultPromise = await target.bind(thisArg, ...argArray)();
                                    // const resultPromise = await target.bind(thisArg, ...argArray)()
                                    return resultPromise;
                                } catch (e) {
                                    if (e.message == "memory access out of bounds") {
                                        console.error(e)
                                        __wbg_reset_state();
                                        state.abort("Call to DO panicked, force-restarting DO")
                                        return new Response("Worker panicked... restarting DO")
                                    }
                                    throw e;
                                }


                            }
                        });
                    }
                    return original; // Return the property directly if it's not a function
                }
            });

        } catch (err) {
            __wbg_reset_state();
            state.abort("Constructor for DO panicked, force-restarting DO")
        }
    },
});

export { DOProxy as Sequencer, Batcher, Cleaner, WorkerEntrypointProxy as default };
