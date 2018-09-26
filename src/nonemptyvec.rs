/// A simple-minded NonEmptyVec implementation
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NonEmptyVec<T> {
    first: T,
    rest: Vec<T>,
}

#[derive(Debug)]
pub struct EmptyVectorErr;

impl<T> NonEmptyVec<T>
where
    T: Clone,
{
    pub fn new_first(first: T) -> Self {
        NonEmptyVec {
            first,
            rest: vec![],
        }
    }
    pub fn new(first: T, rest: Vec<T>) -> Self {
        NonEmptyVec { first, rest }
    }
    pub fn new_last(first_v: &[T], tail: NonEmptyVec<T>) -> Self {
        NonEmptyVec::try_from(first_v)
            .map(|nev| nev.concat(&tail))
            .unwrap_or_else(|_e| tail)
    }

    pub fn first(&self) -> &T {
        &self.first
    }
    pub fn rest(&self) -> &Vec<T> {
        &self.rest
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.clone().into()
    }

    pub fn try_from(v: &[T]) -> Result<NonEmptyVec<T>, EmptyVectorErr> {
        if v.is_empty() {
            Err(EmptyVectorErr)
        } else {
            let first = v[0].clone();
            let rest = v[1..].to_vec();
            Ok(NonEmptyVec { first, rest })
        }
    }

    pub fn concat(&self, b: &NonEmptyVec<T>) -> NonEmptyVec<T> {
        let mut c = self.rest.clone();
        c.append(&mut b.to_vec());
        NonEmptyVec::new(self.first.clone(), c)
    }

    pub fn last(&self) -> &T {
        self.rest.last().unwrap_or(&self.first)
    }

    pub fn len(&self) -> usize {
        self.rest.len() + 1
    }
}

impl<T> Into<Vec<T>> for NonEmptyVec<T> {
    fn into(mut self) -> Vec<T> {
        let mut tmp = vec![self.first];
        tmp.append(&mut self.rest);
        tmp
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn nonempty_construct_good() {
        let nev = NonEmptyVec::new_first(1);
        assert_eq!(1, nev.first);
        let expected1: Vec<i32> = vec![];
        assert_eq!(expected1, nev.rest);

        let nev2 = NonEmptyVec::new(1, vec![2, 3]);
        assert_eq!(1, nev2.first);
        assert_eq!(vec![2, 3], nev2.rest);
    }

    #[test]
    fn nonempty_vec_to_vec() {
        let nev = NonEmptyVec::new_first(1);
        let v1: Vec<i32> = nev.into();
        assert_eq!(vec![1], v1);

        let nev2 = NonEmptyVec::new(1, vec![2, 3, 4]);
        assert_eq!(vec![1, 2, 3, 4], Into::<Vec<i32>>::into(nev2));
    }
}
