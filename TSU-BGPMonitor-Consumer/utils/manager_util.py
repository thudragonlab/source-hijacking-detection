from multiprocessing import Manager

manager = Manager()
lock = manager.Lock()

def get_manager():
    return manager

def get_lock():
    return lock