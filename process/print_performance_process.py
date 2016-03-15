"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import datetime
import os
import signal
import sys
import time

sys.path.append(os.path.abspath('../'))
import config


def signal_handler(signal, frame):
    sys.exit(0)


def get_time(time_value):
    return "[{}]".format(datetime.timedelta(seconds=time_value))


def get_time_date(time_value):
    return "[{}]".format(datetime.datetime.fromtimestamp(time_value).strftime('%d/%m/%y:%H:%M:%S'))


def print_perf_server(max_num_of_tasks, timeout, connection_list):
    start_time = time.time()

    while True:
        time.sleep(config.PRINT_PERFORMANCE_SERVER_TIMEOUT)
        total = 0
        for element in connection_list:
            total += element[1].value

        if total != 0:
            new_time = time.time()
            raw_value = float(total) / (float(new_time) - float(start_time))
            print "Jobs Done: " + str(total) + " \tPerformance: " + str(round(raw_value, 2)) + " t/s"
        else:
            print "\nClients:"

        for element in connection_list:
            print "\t" + element[0] + " \t",
            if element[2].is_alive():
                print "Condition: alive \t",
            else:
                print "Condition: dead  \t",
            print "Jobs Done: " + str(element[1].value) + "  \t",
            print "'Connection Time: " + get_time_date(element[3])
        print ""


def print_perf(max_num_of_tasks, sm_tasks_num):
    signal.signal(signal.SIGINT, signal_handler)
    start_time = time.time()
    old = 0
    while True:
        tmp = sm_tasks_num.value

        if tmp == max_num_of_tasks and max_num_of_tasks != 0:
            # We are done with the tasks, display final time
            print("{}\t Running time: {}".format(get_time_date(time.time()), get_time(time.time() - start_time)))
            return

        else:
            new_time = time.time()
            raw_value = float(tmp) / (float(new_time) - float(start_time))
            value = round(raw_value, 2)

            if raw_value != 0:
                remaining_time = (max_num_of_tasks - tmp) / raw_value
            else:
                remaining_time = 0.0

            if remaining_time != 0.0 and max_num_of_tasks != 0:
                progress = "{} {} t/s \tREAL:\t{}t/s \ttc:\t{}/{} \trunning time:\t{} \tETA:\t{}".format(
                    get_time_date(time.time()),
                    value,
                    round(float((tmp - old) / (float(config.PRINT_PERFORMANCE_TIMEOUT))), 2),
                    tmp,
                    max_num_of_tasks,
                    get_time(time.time() - start_time),
                    get_time(remaining_time)
                )
                print(progress)

            else:
                value = max_num_of_tasks
                if max_num_of_tasks == 0:
                    value = '-'
                progress = "{} REAL:\t{}t/s \ttc:\t{}/{} \ttime elapsed:\t{}".format(
                    get_time_date(time.time()),
                    round(float((tmp - old) / (float(config.PRINT_PERFORMANCE_TIMEOUT))), 2),
                    tmp,
                    value,
                    get_time(time.time() - start_time),
                )
                print(progress)

            time.sleep(config.PRINT_PERFORMANCE_TIMEOUT)

        old = tmp
