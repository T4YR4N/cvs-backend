interface QueueNode<T> {
    value: T
    next: QueueNode<T> | undefined
}

class Queue<T> {
    #HEAD: QueueNode<T> | undefined
    #LAST: QueueNode<T> | undefined
    callbackForFirstEntry: () => void = () => {}

    constructor(callbackForFirstEntry: () => void) {
        this.#HEAD = undefined
        this.#LAST = undefined
        this.callbackForFirstEntry = callbackForFirstEntry
    }

    enqueue(value: T) {
        const link: QueueNode<T> = { value, next: undefined }

        const wasEmpty = !this.#HEAD && !this.#LAST

        if (this.#LAST) {
            this.#LAST.next = link
            this.#LAST = link
        } else {
            this.#HEAD = link
            this.#LAST = link
        }

        if (wasEmpty) {
            this.callbackForFirstEntry()
        }
    }

    /**
     * It dequeues the first element in the queue and returns it. If the parameter beforeDequeueing is provided, it will be called with the element as aparameter before the element is dequeued, providing the element to be dequeued is not undefined.
     * @param beforeDequeueing - A function that will be called with the element to be dequeued as a parameter before the element is dequeued.
     * @returns The first element in the queue.
     */
    async dequeue(beforeDequeueing?: (value: T) => Promise<void>) {
        if (!this.#HEAD) return

        if (beforeDequeueing) await beforeDequeueing(this.#HEAD.value)

        const first = this.#HEAD.value
        this.#HEAD = this.#HEAD.next
        if (!this.#HEAD) this.#LAST = undefined
        return first
    }

    peek(): T | undefined {
        return this.#HEAD ? this.#HEAD.value : undefined
    }
}

// https://codereview.stackexchange.com/questions/255698/queue-with-o1-enqueue-and-dequeue-with-js-arrays

export default Queue
