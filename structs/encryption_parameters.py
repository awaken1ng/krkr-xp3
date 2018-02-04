encryption_parameters = {
    # Master key, secondary key, XOR the first byte, segment name (for packing)
    'none':            (0x00000000, 0x00, False, b'eliF'),
    'neko_vol1':       (0x1548E29C, 0xD7, False, b'eliF'),
    'neko_vol1_steam': (0x44528B87, 0x23, False, b'eliF'),
    'neko_vol0':       (0x1548E29C, 0xD7, True,  b'neko'),
    'neko_vol0_steam': (0x44528B87, 0x23, True,  b'neko')
}
