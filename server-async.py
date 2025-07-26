import asyncio
import iectypes
import random
import sys
import socket
import time
from os import path
from os import mkdir

from iec101srv import Point, Server101

# IEC101 server settings
HOST = "127.0.0.1"  # Client address (empty means "any address")
PORT = 4001  # Port to listen on (non-privileged ports are > 1023)
ASDU_ADDR = 1
BACKGROUND = True
MAX_CONNECTIONS = 3

# Logging settings (Higher level -> more messages)
LOGLEVEL = 1
PRINTLEVEL = 1

# ASDU settings
DEF_TIMEZONE = 3 * 3600

#Discrete signals
DEF_DISCRSTART = 1
DEF_DISCRCOUNT = 48

#Analog signals
DEF_MEASSTART = 1001
DEF_MEASCOUNT = 32

# Signal update time sets randomly between DEF_MINUPDATE and DEF_MAXUPDATE
DEF_MINUPDATE = 5
DEF_MAXUPDATE = 300
# DEF_MAXUPDATE = max(DEF_DISCRCOUNT,DEF_MEASCOUNT)/3 

# Data corruption settings
# Don't parse FT12 frames when grinder is enabled otherwise scapy may crash! (loglevel and printlevel should be < 2)
GRIND = False
MIRRORLOG = True
PROBABILITY = 16


def grinder(data: bytes, logging: bool = MIRRORLOG) -> bytes:

    if data is None or not GRIND:
        return data

    array = bytearray(data)
    match random.randint(0, PROBABILITY):
        case 0:  # insert random bytes
            ins_point = random.randint(0, len(array))
            array = (
                array[:ins_point]
                + bytearray(random.randbytes(random.randint(0, 32)))
                + array[ins_point:]
            )
        case 1:  # delete random bytes
            ins_point = random.randint(0, len(array))
            end_point = random.randint(ins_point, len(array))
            array = array[:ins_point] + array[end_point:]
        case 2:  # replace random byte
            ins_point = random.randint(0, len(array) - 1)
            array[ins_point] = random.randint(0, 255)
        case _:
            return data

    if logging:
        print("Built==>", data.hex("-"))

    data = bytes(array)

    if logging:
        print("Grind==>", data.hex("-"))

    return data


class Point_sc(Point):

    def check(self) -> None:
        pass


class Meas(Point_sc):
    # M_ME_

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.nexttime = time.time()

    def check(self) -> None:
        def measuregen(oldvalue: float):
            if oldvalue:
                return oldvalue * 0.99 + random.gauss(mu=0.0, sigma=0.10)
            else:
                return random.gauss(mu=0.0, sigma=0.10)

        if self.nexttime < time.time():
            self.set(
                value=measuregen(self.value), flags=0, time=time.time() + DEF_TIMEZONE
            )
            self.nexttime = time.time() + random.uniform(DEF_MINUPDATE, DEF_MAXUPDATE)


class Discr(Point_sc):
    # M_SP_

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.nexttime = time.time()

    def check(self) -> None:
        if self.nexttime < time.time():
            self.set(
                value=random.getrandbits(1), flags=0, time=time.time() + DEF_TIMEZONE
            )
            self.nexttime = time.time() + random.uniform(DEF_MINUPDATE, DEF_MAXUPDATE)


def makepath(logname: str, *folders: str) -> str:
    logpath = path.dirname(__file__)
    for f in folders:
        logpath = path.join(logpath, f)
        if not path.exists(logpath):
            mkdir(logpath)
    return path.join(logpath, logname)


async def process(set_of_pnts: list[Point_sc]) -> None:
    while True:
        # Process imitation
        for pnt in set_of_pnts:
            pnt.check()
        await asyncio.sleep(0.25)


async def main():

    # monitoring points preparation - Measurements
    set_of_points = []
    for i in range(DEF_MEASCOUNT):
        set_of_points.append(
            Meas(
                type=iectypes.Type.M_ME_NC_1,
                io_address=i + DEF_MEASSTART,
                value=i,
                flags=0,
            )
        )
    # monitoring points preparation - Discrete points
    for i in range(DEF_DISCRCOUNT):
        set_of_points.append(
            Discr(
                type=iectypes.Type.M_SP_NA_1,
                io_address=i + DEF_DISCRSTART,
                value=True,
                flags=0,
            )
        )

        # Starting separate data generating task
        task1 = asyncio.create_task(process(set_of_points))

    servers = []  # servers list

    async def conn_accept(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Creating callable connection accept processor
        Creates new server when new connection is accepted
        and removes when connection is closed
        """
        if len(servers) >= MAX_CONNECTIONS:
            print("Connection was rejected")
            writer.close()
            return

        # log file path
        logname = makepath(
            "iec101_{}.log".format(time.strftime("%y-%m-%d-%H-%M-%S")), "logs"
        )

        with open(logname, "a", buffering=-1) as logfile:

            # Create iec101 server...
            srv101 = Server101(
                ASDU_ADDR, BACKGROUND, grinder, logfile, PRINTLEVEL, LOGLEVEL
            )
            servers.append(srv101)
            if logfile is not None:
                logfile.write("Server instance: " + str(srv101) + "\n")
            print("Server added:", srv101, "Count:", len(servers))
            # ...and add points to it
            for p in set_of_points:
                srv101.add_point(p)

            # Start iec101 server
            await srv101.conn_handle_async(reader, writer)
            # Destroy
            srv101.del_all_points()
            servers.remove(srv101)
            print("Server removed: ", srv101, "Count:", len(servers))

    # Creating TCP socket
    s = await asyncio.start_server(conn_accept, HOST, PORT)

    try:
        async with s:
            await s.serve_forever()

    except KeyboardInterrupt:
        sys.exit()


if __name__ == "__main__":
    asyncio.run(main())
