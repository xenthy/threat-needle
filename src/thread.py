import threading


class Thread:
    __interrupt = False

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
