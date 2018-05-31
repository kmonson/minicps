from bacpypes.core import run, stop

from bacpypes.primitivedata import Unsigned, Enumerated, Integer, Null, Real
from bacpypes.constructeddata import Array, Choice, Any, Atomic
from bacpypes.app import BIPSimpleApplication
from bacpypes.local.device import LocalDeviceObject
from bacpypes.object import get_object_class, get_datatype

from bacpypes.service.object import ReadWritePropertyMultipleServices
from bacpypes.pdu import Address

from bacpypes.task import RecurringTask

from bacpypes.apdu import (ReadPropertyRequest,
                           WritePropertyRequest,
                           Error,
                           AbortPDU,
                           RejectPDU,
                           ReadPropertyACK,
                           SimpleAckPDU,
                           ReadPropertyMultipleRequest,
                           ReadPropertyMultipleACK,
                           ConfirmedRequestSequence)

import threading

from Queue import Queue, Empty

import logging

# some debugging
_log = logging.getLogger(__name__)


def create_application(interface_str, device_name, device_id, config_list):

    _log.debug("    - creating application")
    # make a device object
    this_device = LocalDeviceObject(
        objectName=device_name,
        objectIdentifier=device_id,
        maxApduLengthAccepted=1024,
        segmentationSupported="segmentedBoth",
        vendorIdentifier=15
    )

    # make a sample application
    this_application = Application(this_device, interface_str)

    # Currently we don't actually enforce read only properties.
    for register in config_list:
        _log.debug("    - creating object of type: %s, %i" % (register["type"],
                                                             register["index"]))
        klass = get_object_class(register["type"])
        ravo = klass(objectIdentifier=(register["type"], register["index"]),
                     objectName=register["name"], description=register.get("description",""))

        ravo.WriteProperty("presentValue", 0, direct=True)

        this_application.add_object(ravo)

    return this_application


class IOCB:
    def __init__(self, request=None, request_self=False, shutdown=False):
        # requests and responses
        self.ioRequest = request
        self.event = threading.Event()
        self.return_value = None
        self.exception = None
        self.shutdown=shutdown
        self.request_self = request_self

    def set(self, value):
        if not (self.return_value is None and self.exception is None):
            _log.error("IOCB set called after previous set or set_exception call")
        self.return_value = value
        self.event.set()

    def set_exception(self, exception):
        if not (self.return_value is None and self.exception is None):
            _log.error("IOCB set_exception called after previous set or set_exception call")
        self.exception = exception
        self.event.set()

    def get(self, timeout=None):
        self.event.wait(timeout)
        if self.exception is not None:
            raise self.exception
        return self.return_value



#
#   ReadPropertyMultipleApplication
#

class Application(BIPSimpleApplication,
                  RecurringTask,
                  ReadWritePropertyMultipleServices):
    def __init__(self, *args, **kwargs):
        BIPSimpleApplication.__init__(self, *args, **kwargs)
        RecurringTask.__init__(self, 20)

        self.request_queue = Queue()

        # assigning invoke identifiers
        self.nextInvokeID = 1

        # keep track of requests to line up responses
        self.iocb = {}

        self.install_task()
        self.server_thread = None

    def start_application(self):
        if self.server_thread is not None and self.server_thread.is_alive():
            raise RuntimeError("Application is already running.")
        kwargs = {"spin": 0.1,
                  "sigterm": None,
                  "sigusr1": None}
        self.server_thread = threading.Thread(target=run, kwargs=kwargs)

        # exit the BACnet App thread when the main thread terminates
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop_application(self):
        if not self.is_running():
            _log.warning("BACnet application is not currently running.")
            return
        iocb = IOCB(shutdown=True)
        self.submit_request(iocb)

    def is_running(self):
        return self.server_thread is not None and self.server_thread.is_alive()

    def process_task(self):
        while True:
            try:
                iocb = self.request_queue.get(False)
            except Empty:
                break

            self.handle_request(iocb)

    def submit_request(self, iocb):
        self.request_queue.put(iocb)

    def get_next_invoke_id(self, addr):
        """Called to get an unused invoke ID."""

        initialID = self.nextInvokeID
        while 1:
            invokeID = self.nextInvokeID
            self.nextInvokeID = (self.nextInvokeID + 1) % 256

            # see if we've checked for them all
            if initialID == self.nextInvokeID:
                raise RuntimeError("no available invoke ID")

            # see if this one is used
            if (addr, invokeID) not in self.iocb:
                break

        return invokeID

    def handle_request(self, iocb):
        if iocb.shutdown:
            stop()
            return
        apdu = iocb.ioRequest

        if isinstance(apdu, ConfirmedRequestSequence):
            # if iocb.request_self:
            #     self._handle_self_request(iocb)
            #     return

            # assign an invoke identifier
            apdu.apduInvokeID = self.get_next_invoke_id(apdu.pduDestination)

            # build a key to reference the IOCB when the response comes back
            invoke_key = (apdu.pduDestination, apdu.apduInvokeID)

            # keep track of the request
            self.iocb[invoke_key] = iocb

        try:
            self.request(apdu)
        except StandardError as e:
            iocb.set_exception(e)

    # def _handle_self_request(self, iocb):
    #     apdu = iocb.ioRequest

    def request(self, apdu):
        _log.debug("DEBUG: request: {} {}".format(apdu.pduDestination, self.localAddress))

        if (apdu.pduDestination == self.localAddress):
            apdu.pduSource = apdu.pduDestination
            self.indication(apdu)
        else:
            super(Application, self).request(apdu)

    def response(self, apdu):
        _log.debug("DEBUG: response: {} {}".format(apdu.pduDestination, self.localAddress))

        if (apdu.pduDestination == self.localAddress):
            apdu.pduSource = apdu.pduDestination
            self.confirmation(apdu)
        else:
            super(Application, self).response(apdu)

    def _get_iocb_key_for_apdu(self, apdu):
        return (apdu.pduSource, apdu.apduInvokeID)


    def _get_iocb_for_apdu(self, apdu, invoke_key):
        _log.debug("DEBUG: _get_iocb_for_apdu invoke key: {}".format(invoke_key))
        # find the request
        working_iocb = self.iocb.get(invoke_key, None)
        if working_iocb is None:
            _log.error("no matching request for confirmation")
            return None
        del self.iocb[invoke_key]

        if isinstance(apdu, AbortPDU):
            working_iocb.set_exception(RuntimeError(
                "Device communication aborted: " + str(apdu)))
            return None

        elif isinstance(apdu, Error):
            working_iocb.set_exception(RuntimeError(
                "Error during device communication: " + str(apdu)))
            return None
        elif isinstance(apdu, RejectPDU):
            working_iocb.set_exception(
                RuntimeError("Device at {source} rejected the request:"
                             " {reason}".format(
                                 source=apdu.pduSource,
                                 reason=apdu.apduAbortRejectReason)))
            return None
        else:
            return working_iocb

    def _get_value_from_read_property_request(self, apdu, datatype, working_iocb):
        # special case for array parts, others are managed by cast_out
        if issubclass(datatype, Array) and (
                apdu.propertyArrayIndex is not None):
            if apdu.propertyArrayIndex == 0:
                value = apdu.propertyValue.cast_out(Unsigned)
            else:
                value = apdu.propertyValue.cast_out(datatype.subtype)
        else:
            value = apdu.propertyValue.cast_out(datatype)
            if issubclass(datatype, Enumerated):
                value = datatype(value).get_long()
        return value

    def _get_value_from_property_value(self, propertyValue,
                                       datatype):
        value = propertyValue.cast_out(datatype)
        if issubclass(datatype, Enumerated):
            value = datatype(value).get_long()

        try:
            if issubclass(datatype, Array) and (
                    issubclass(datatype.subtype, Choice)):
                new_value = []
                for item in value.value[1:]:
                    result = item.dict_contents().values()
                    if result[0] != ():
                        new_value.append(result[0])
                    else:
                        new_value.append(None)
                value = new_value
        except StandardError as e:
            _log.exception(e)
            raise e
        return value

    def confirmation(self, apdu):
        # return iocb if exists, otherwise sets error and returns
        invoke_key = self._get_iocb_key_for_apdu(apdu)
        working_iocb = self._get_iocb_for_apdu(apdu, invoke_key)
        if not working_iocb:
            return

        if (isinstance(working_iocb.ioRequest, ReadPropertyRequest) and
                isinstance(apdu, ReadPropertyACK)):
            datatype = get_datatype(apdu.objectIdentifier[0],
                                    apdu.propertyIdentifier)
            if not datatype:
                working_iocb.set_exception(TypeError("unknown datatype"))
                return

            working_iocb.set(
                self._get_value_from_read_property_request(apdu, datatype, working_iocb))

        elif (isinstance(working_iocb.ioRequest, WritePropertyRequest) and
              isinstance(apdu, SimpleAckPDU)):
            working_iocb.set(apdu)
            return

        elif (isinstance(working_iocb.ioRequest,
                         ReadPropertyMultipleRequest) and
              isinstance(apdu, ReadPropertyMultipleACK)):

            result_dict = {}
            for result in apdu.listOfReadAccessResults:
                # here is the object identifier
                objectIdentifier = result.objectIdentifier

                # now come the property values per object
                for element in result.listOfResults:
                    # get the property and array index
                    propertyIdentifier = element.propertyIdentifier
                    propertyArrayIndex = element.propertyArrayIndex

                    # here is the read result
                    readResult = element.readResult

                    # check for an error
                    if readResult.propertyAccessError is not None:
                        error_obj = readResult.propertyAccessError

                        msg = 'ERROR DURING SCRAPE of {2} (Class: {0} Code: {1})'
                        _log.error(msg.format(error_obj.errorClass,
                                              error_obj.errorCode,
                                              objectIdentifier))

                    else:
                        # here is the value
                        propertyValue = readResult.propertyValue

                        # find the datatype
                        datatype = get_datatype(objectIdentifier[0],
                                                propertyIdentifier)
                        if not datatype:
                            working_iocb.set_exception(
                                TypeError("unknown datatype"))
                            return

                        # special case for array parts, others are managed
                        # by cast_out
                        valid = True
                        value = None
                        if issubclass(datatype, Array) and (
                                propertyArrayIndex is not None):
                            if propertyArrayIndex == 0:
                                value = propertyValue.cast_out(Unsigned)
                            else:
                                value = propertyValue.cast_out(datatype.subtype)
                        else:
                            try:
                                value = self._get_value_from_property_value(
                                    propertyValue, datatype, working_iocb)
                            except StandardError as e:
                                valid = False

                        if valid:
                            result_dict[objectIdentifier[0], objectIdentifier[1],
                                        propertyIdentifier,
                                        propertyArrayIndex] = value

            working_iocb.set(result_dict)

        else:
            _log.error("For invoke key {key} Unsupported Request Response pair"
                       " Request: {request} Response: {response}".
                       format(key=invoke_key, request=working_iocb.ioRequest,
                              response=apdu))
            working_iocb.set_exception(TypeError('Unsupported Request Type'))


