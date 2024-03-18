use nom::IResult;

use crate::ike::IkeV1;

pub async fn parse_ike_v1(i: &[u8]) -> IResult<&[u8], IkeV1> {}
