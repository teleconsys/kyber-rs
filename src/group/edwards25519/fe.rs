pub fn load3(input: &[u8]) -> i64 {
    let mut r = input[0] as i64;
    r |= (input[1] as i64) << 8;
    r |= (input[2] as i64) << 16;
    r
}

pub fn load4(input: &[u8]) -> i64 {
    let mut r = input[0] as i64;
    r |= (input[1] as i64) << 8;
    r |= (input[2] as i64) << 16;
    r |= (input[3] as i64) << 24;
    r
}
