import threading


class Thread:
    __interrupt = False
    __event = None

    @staticmethod
    def set_name(name):
        threading.current_thread().setName(name)

    @staticmethod
    def name():
        return threading.current_thread().getName()

    @staticmethod
    def set_interrupt(interrupt):
        Thread.__interrupt = interrupt

    @staticmethod
    def get_interrupt():
        return Thread.__interrupt


def thread(name=None, daemon=False):
    """
    Creates a thread for a given function
    """
    def wrapper(function):
        def decorator_thread(*args):
            thread = threading.Thread(target=function, args=args, daemon=daemon)
            if name != None:
                thread.setName(name)
            thread.start()
            return thread
        return decorator_thread
    return wrapper
