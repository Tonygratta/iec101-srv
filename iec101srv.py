import iec101
import iectypes
import random
import time
import typing
import asyncio
import socket
from iec101 import FT12Frame, FT12Fixed, FT12Variable, FT12Single, ASDU
from typing import Any, Optional


class Point:

    def __init__(
        self,
        type: int,
        io_address: int,
        value: Any = None,
        flags: Optional[int] = None,
        time: Optional[float] = None,
        server: Optional[Any] = None,
    ):
        self.server = []
        if server is not None:
            self.server.append(server)
        self.type = type
        self.io_address = io_address
        self.value = value
        self.flags = flags
        self.time = time

    def srv_register(self, srv: object) -> None:
        self.server.append(srv)

    def srv_deregister(self, srv: object) -> None:
        try:
            while True:
                self.server.remove(srv)
        except ValueError:
            return

    def set(
        self,
        value: Any = None,
        flags: Optional[int] = None,
        time: Optional[float] = None,
    ) -> None:
        if value is not None:
            self.value = value
        if flags is not None:
            self.flags = flags
        if time is not None:
            self.time = time

        for s in self.server:
            s.add_event(self, iectypes.Cot.SPONT)


class Event:

    def __init__(
        self,
        point: Point,
        cot: int,
        value: Any = None,
        flags: Optional[int] = None,
        time: Optional[float] = None,
    ):
        """
        If (value or flags or time) is None then
        we should pick all three of them
        from the point at the moment of
        packet generating
        """
        self.point = point
        self.cot = cot
        self.value = None
        self.flags = None
        self.time = None

        # !!! This needs to be deleted AFTER refactoring
        if value is not None:
            self.value = value
        else:
            self.value = self.point.value

        if flags is not None:
            self.flags = flags
        else:
            self.flags = self.point.flags

        if time is not None:
            self.time = time
        else:
            self.time = self.point.time

    # !!! This needs to be deleted AFTER refactoring
    def exists(self) -> bool:
        return (
            (self.point is not None)
            and (self.cot is not None)
            and (self.value is not None)
            and (self.flags is not None)
            and (self.time is not None)
        )


class Eventpack:
    def __init__(self):
        self.evts = []
        self.cot = None
        self.type = None
        self.time = None
        self.sq = None


class Eventpack_evlist(Eventpack):

    def __init__(self, evlist: list[Event]):
        super().__init__()
        if len(evlist) > 0:
            self.ev = evlist.pop(0)
            if self.ev.exists():
                self.evts.append(self.ev)
                self.cot = self.ev.cot
                self.type = self.ev.point.type
                self.time = self.ev.time
            self.sq = 0


class Eventpack_points(Eventpack):

    def __init__(self, points: list[Point], cot: int):
        super().__init__()
        if len(points) > 0:
            self.ev = Event(points.pop(0), cot)
            self.cot = cot
            if self.ev.exists():
                self.evts.append(self.ev)
                self.type = self.ev.point.type
            self.time = time.time()
            self.sq = 0


class Server101:

    def __init__(
        self,
        asdu_addr: int,
        backgrnd: bool = False,
        postproc: Optional[typing.Callable] = None,
        logfile: Optional[typing.TextIO] = None,
        printlvl: int = 0,
        loglvl: int = 0,
    ):
        self.asdu_addr = asdu_addr
        self.backgrnd = backgrnd
        self.postprocessing = postproc
        self.points: list[Point] = []  # List of points available for this server
        self.last_point_get = 0
        self.events: list[Event] = []  # Events list for class 1 data transmission
        self.inrglist: list[Point] = (
            []
        )  # Points list for inrogen data prep and transmission
        self.state = -1  # -1: channel is not reset; 0: channel is reset
        self.acd = False
        self.dfc = False
        self.fcb = False
        self.logfile = logfile
        self.printlvl = printlvl
        self.loglvl = loglvl

    def channel_reset(self) -> None:
        self.state = 0
        self.fcb = False

    def channel_unreset(self) -> None:
        self.state = -1

    def add_point(self, pt: Point) -> None:
        self.points.append(pt)
        pt.srv_register(self)

    def add_points(self, pts: list[Point]) -> None:
        self.points = pts
        for pt in pts:
            pt.srv_register(self)

    def del_all_points(self) -> None:
        for p in self.points:
            p.srv_deregister(self)
        self.points.clear()

    def add_event(self, *args, **kwargs) -> None:
        # Adds event to Event list when point has changed
        self.events.append(Event(*args, **kwargs))

    def start_inrogen(self) -> None:
        for point in self.points:
            if point not in self.inrglist:
                self.inrglist.append(point)

    def fcs_calc2(self, frame: FT12Frame) -> FT12Frame:
        # Frame checksum calculation
        # Fixed and Variable frame types
        match frame.build()[0]:
            case 16:
                payld = frame.build()[1:-2]
            case 104:
                payld = frame.build()[4:-2]
            case _:
                return frame
        pl_sum = 0
        for pl_byte in payld:
            pl_sum = pl_sum + pl_byte
        frame.checksum = pl_sum % 256
        return frame

    def get_ctrl(self) -> int:
        # Generating Control flags using current server state
        control = 0
        if self.dfc:
            control = control + 1
        if len(self.events) > 0:
            control = control + 2  # acd - 1class data query
        return control

    def get_siq(self, value: bool, flags: int) -> int:
        siq = 1 if value else 0
        return flags + siq

    def get_next_point(self) -> list[Point]:
        # Getting points sequentally from the self.points list for the sake of background scan
        pointlist: list[Point] = []
        try:
            pointlist.append(self.points[self.last_point_get])
            if self.last_point_get < (len(self.points) - 1):
                self.last_point_get = self.last_point_get + 1
            else:
                self.last_point_get = 0
        except IndexError:
            pass
        return pointlist

    def gen_resp(self, evpack: Eventpack) -> FT12Frame:
        # Что-то с генерацией значений ShortFloat и значений и флагов SIQ в iec101

        if len(evpack.evts) == 0:
            return FT12Frame() / FT12Fixed(
                Control_Flags=self.get_ctrl(), fcode=9, address=self.asdu_addr
            )
        ev = evpack.evts[0]
        match evpack.type:
            case iectypes.Type.M_SP_NA_1:
                resp = FT12Frame() / FT12Variable(
                    LinkUserData=ASDU(
                        VSQ=iec101.VSQ(SQ=0, number=1),
                        type=iectypes.Type.M_SP_NA_1,
                        COT=ev.cot,
                        CommonAddress=self.asdu_addr,
                        IO=iec101.IO1(
                            IOA=ev.point.io_address,
                            SIQ=self.get_siq(ev.value, ev.flags),
                        ),
                    ),
                    Control_Flags=self.get_ctrl(),
                    length_1=9,
                    length_2=9,
                    fcode=8,
                    address=1,
                )
            case iectypes.Type.M_ME_NC_1:
                resp = FT12Frame() / FT12Variable(
                    LinkUserData=ASDU(
                        VSQ=iec101.VSQ(SQ=0, number=1),
                        type=iectypes.Type.M_ME_NC_1,
                        COT=ev.cot,
                        CommonAddress=self.asdu_addr,
                        IO=iec101.IO13(
                            IOA=ev.point.io_address,
                            value=[
                                iec101.ShortFloat(value=ev.value, QDS=ev.flags),
                            ],
                        ),
                    ),
                    Control_Flags=self.get_ctrl(),
                    length_1=13,
                    length_2=13,
                    fcode=8,
                    address=1,
                )
            case _:
                ### Can't send this type of event, sending 'Data unavailable'
                resp = FT12Frame() / FT12Fixed(
                    Control_Flags=self.get_ctrl(), fcode=9, address=self.asdu_addr
                )

        return resp

    def userdata_proc(self, frame: FT12Frame) -> FT12Frame:
        match frame.LinkUserData.type:
            case 100:
                self.start_inrogen()
                return FT12Frame() / FT12Fixed(
                    Control_Flags=self.get_ctrl(), fcode=0, address=self.asdu_addr
                )
            case _:
                return FT12Frame() / FT12Fixed(
                    Control_Flags=self.get_ctrl(), fcode=15, address=self.asdu_addr
                )

    ##IEC101 State-machine
    def _when_not_reset(self, frame: FT12Frame) -> Optional[FT12Frame]:
        match frame.fcode:

            case 0:
                self.channel_reset()
                return FT12Frame() / FT12Fixed(
                    Control_Flags=self.get_ctrl(), fcode=0, address=self.asdu_addr
                )

            case 9:
                return FT12Frame() / FT12Fixed(
                    Control_Flags=self.get_ctrl(), fcode=11, address=self.asdu_addr
                )

            case _:
                return None

    def _when_is_reset(self, frame: FT12Frame) -> FT12Frame:
        match frame.fcode:

            case 0:
                self.channel_reset()
                return FT12Frame() / FT12Fixed(
                    Control_Flags=self.get_ctrl(), fcode=0, address=self.asdu_addr
                )

            case 3:
                return self.userdata_proc(frame)

            case 9:
                return FT12Frame() / FT12Fixed(
                    Control_Flags=self.get_ctrl(), fcode=11, address=self.asdu_addr
                )

            case 10:
                if len(self.events) > 0:
                    return self.gen_resp(Eventpack_evlist(self.events))

                else:
                    return FT12Frame() / FT12Fixed(
                        Control_Flags=self.get_ctrl(), fcode=9, address=self.asdu_addr
                    )

            case 11:  # Class 2 query
                if len(self.inrglist) > 0:  # interrogation data
                    return self.gen_resp(
                        Eventpack_points(self.inrglist, iectypes.Cot.INROGEN)
                    )

                else:  # No inrogen data
                    if self.backgrnd:
                        return self.gen_resp(
                            Eventpack_points(
                                self.get_next_point(),
                                iectypes.Cot.BACK,
                            )
                        )
                    else:
                        return FT12Frame() / FT12Fixed(
                            Control_Flags=self.get_ctrl(),
                            fcode=9,
                            address=self.asdu_addr,
                        )  # Send No data

            case _:
                return FT12Frame() / FT12Single()

    ##End of IEC101 State-machine

    def logging(
        self,
        comment: str = "",
        data: Optional[bytes] = None,
        loglevel: int = 1,
        printlevel: int = 1,
    ) -> None:

        if data is not None:
            datahex = data.hex("-")
        else:
            datahex = "(None)"
        if self.logfile is not None:
            if loglevel > 0:
                self.logfile.write(
                    "{}{:.3f} {} {}\n".format(
                        time.strftime("%Y-%m-%d %H:%M:"),
                        time.time() % 60,
                        comment,
                        datahex,
                    )
                )
            if loglevel > 1 and data is not None:
                self.logfile.write(FT12Frame(data).show(dump=True))

        if printlevel > 0:
            print("{} {}".format(comment, datahex))
        if printlevel > 1 and data is not None:
            print(FT12Frame(data).show(dump=True))
        if printlevel > 2 and data is not None:
            print(FT12Frame(data).command())

    def req_processor(self, request: bytes) -> Optional[bytes]:
        frame = FT12Frame(request)
        response = None
        match self.state:
            case -1:
                response = self._when_not_reset(frame)
            case 0:
                response = self._when_is_reset(frame)
        if response is not None:
            return self.fcs_calc2(response).build()
        else:
            return None

    async def conn_handle_async(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                req = await reader.read(512)

                if len(req) > 0:  # Have data for processing
                    # Logging of recieved frame if enabled
                    self.logging("Received", req, self.loglvl, self.printlvl)

                    resp = self.req_processor(req)
                    if resp is not None:

                        # Frame corrupting if enabled
                        if self.postprocessing is not None:
                            resp = self.postprocessing(resp)

                        # Logging of transmitted frame if enabled
                        self.logging("Sent    ", resp, self.loglvl, self.printlvl)
                        if resp is not None:
                            writer.write(resp)  # Sending
                            await writer.drain()

                else:  # Connection has been closed
                    print("Connection has been closed")
                    self.channel_unreset()
                    break
        except ConnectionResetError as ex:
            print("Connection was reset", ex)
            self.channel_unreset()

    def conn_handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                while True:
                    req = conn.recv(512)

                    if len(req) > 0:  # Have data for processing
                        # Logging of recieved frame if enabled
                        self.logging("Received", req, self.loglvl, self.printlvl)

                        resp = self.req_processor(req)
                        if resp is not None:

                            # Frame corrupting if enabled
                            if self.postprocessing is not None:
                                resp = self.postprocessing(resp)
                            if resp is not None:
                                conn.sendall(resp)  # Sending

                            # Logging of transmitted frame if enabled
                            self.logging("Sent    ", resp, self.loglvl, self.printlvl)
                    else:  # Connection has been closed
                        self.channel_unreset()
                        break
            except ConnectionResetError:
                self.channel_unreset()
