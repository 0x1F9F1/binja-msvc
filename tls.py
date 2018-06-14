from binaryninja import Symbol, Type, log
from binaryninja.enums import SymbolType

from utils import BinjaStruct, read_pe_header, check_address


IMAGE_TLS_DIRECTORY32_t = BinjaStruct('<IIIIII', names = ('StartAddressOfRawData', 'EndAddressOfRawData', 'AddressOfIndex', 'AddressOfCallBacks', 'SizeOfZeroFill', 'Characteristics'))
IMAGE_TLS_DIRECTORY64_t = BinjaStruct('<QQQQII', names = ('StartAddressOfRawData', 'EndAddressOfRawData', 'AddressOfIndex', 'AddressOfCallBacks', 'SizeOfZeroFill', 'Characteristics'))

def read_tls_directory(view, address):
    if view.address_size == 4:
        IMAGE_TLS_DIRECTORY_t = IMAGE_TLS_DIRECTORY32_t
    elif view.address_size == 8:
        IMAGE_TLS_DIRECTORY_t = IMAGE_TLS_DIRECTORY64_t
    else:
        raise NotImplementedError()

    tls_directory, address = IMAGE_TLS_DIRECTORY_t.read(view, address)

    return tls_directory, address


def label_tls(view):
    pe = read_pe_header(view)

    tls_data_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]

    if tls_data_directory.Size:
        tls_directory, _ = read_tls_directory(view, view.start + tls_data_directory.VirtualAddress)

        if tls_directory is not None:
            tls_start_address = tls_directory['StartAddressOfRawData']
            tls_end_address = tls_directory['EndAddressOfRawData']
            if (tls_start_address < tls_end_address) and check_address(view, tls_start_address) and check_address(view, tls_end_address):
                log.log_info('TLS Data @ 0x{0:X}'.format(tls_start_address))

                view.define_user_symbol(Symbol(SymbolType.DataSymbol, tls_start_address, 'TlsData'))
                view.define_user_data_var(tls_start_address, Type.array(Type.int(1, sign = False), tls_end_address - tls_start_address))

            tls_index_address = tls_directory['AddressOfIndex']
            if check_address(view, tls_index_address):
                log.log_info('TLS Index @ 0x{0:X}'.format(tls_index_address))

                view.define_user_symbol(Symbol(SymbolType.DataSymbol, tls_index_address, 'TlsIndex'))
                view.define_user_data_var(tls_index_address, Type.int(4, sign = False))
