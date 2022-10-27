use std::ops::Deref;
use std::ops::DerefMut;

pub struct Aggregator {
    a: u32,
}

impl Aggregator {
    fn aggr(&self) -> bool {
        self.a == 1
    }
}

pub struct Dealer {
    aggregator_data: Aggregator,
}

impl Deref for Dealer {
    type Target = Aggregator;

    fn deref(&self) -> &Self::Target {
        &self.aggregator_data
    }
}

impl DerefMut for Dealer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.aggregator_data
    }
}

#[cfg(test)]
mod test {
    use crate::share::vss::rabin::a::{Aggregator, Dealer};

    #[test]
    fn simple_test() {
        let d1 = Dealer {
            aggregator_data: Aggregator { a: 0 },
        };
        let d2 = Dealer {
            aggregator_data: Aggregator { a: 1 },
        };
        assert_eq!(d1.aggr(), false);
        assert_eq!(d2.aggr(), true);
    }
}
