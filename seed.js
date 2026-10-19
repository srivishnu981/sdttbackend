const db = require('./db.JS');

// Roll numbers 25BCS108 .. 25BCS215 (108 students) with random-looking names
const first = ['Aarav','Vihaan','Aditya','Arjun','Rohan','Karthik','Rahul','Sanjay','Varun','Nikhil',
  'Ananya','Priya','Sneha','Divya','Kavya','Meera','Pooja','Ishita','Neha','Shreya',
  'Harsha','Manoj','Suresh','Deepak','Vikram','Kiran','Lakshmi','Revathi','Swathi','Tejas'];
const last = ['Sharma','Rao','Reddy','Nair','Patil','Kulkarni','Gowda','Hegde','Shetty','Naik',
  'Desai','Joshi','Iyer','Menon','Kumar','Singh','Bhat','Pai','Gupta','Verma'];

const insert = db.prepare('INSERT OR IGNORE INTO students (roll_no, name) VALUES (?, ?)');

const seed = db.transaction(() => {
  for (let n = 108; n <= 215; n++) {
    const roll = `25BCS${n}`;
    const i = n - 108;
    const name = `${first[i % first.length]} ${last[(i * 7 + 3) % last.length]}`;
    insert.run(roll, name);
  }
});

seed();
const count = db.prepare('SELECT COUNT(*) AS c FROM students').get().c;
console.log(`Students in DB: ${count}`);