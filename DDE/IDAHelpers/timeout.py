import threading
import thread

def quit_function(fn_name):
    print(f"Func {fn_name} aborted: timeout reached")
    thread.interrupt_main() # raises KeyboardInterrupt

def exit_after(seconds):
    def outer(fn):
        def inner(*args, **kwargs):
            timer = threading.Timer(seconds, quit_function, args=[fn.__name__])
            timer.start()
            try:
                result = fn(*args, **kwargs)
            finally:
                timer.cancel()
            return result
        return inner
    return outer