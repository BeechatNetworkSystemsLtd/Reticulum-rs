use std::collections::{HashSet, VecDeque};

pub struct CacheSet<T: std::hash::Hash + Eq + Clone> {
    capacity: usize,
    set: HashSet<T>,
    queue: VecDeque<T>,
}

impl<T: std::hash::Hash + Eq + Clone> CacheSet<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            set: HashSet::new(),
            queue: VecDeque::new(),
        }
    }

    pub fn insert(&mut self, value: &T) -> bool {
        if self.set.contains(&value) {
            return false;
        }

        if self.set.len() == self.capacity {
            if let Some(oldest) = self.queue.pop_front() {
                self.set.remove(&oldest);
            }
        }

        self.set.insert(value.clone());
        self.queue.push_back(value.clone());

        return true;
    }

    pub fn contains(&self, value: &T) -> bool {
        self.set.contains(&value)
    }
}
