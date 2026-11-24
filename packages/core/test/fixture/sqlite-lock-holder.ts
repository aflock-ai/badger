import { Database } from "bun:sqlite"

// Holds an exclusive lock on a database for a moment, the way a server's last connection does while
// it checkpoints and removes the WAL on close. Prints "locked" once the lock is held.
const db = new Database(process.argv[2])
db.run("PRAGMA locking_mode = EXCLUSIVE")
db.run("BEGIN EXCLUSIVE")
db.run("CREATE TABLE IF NOT EXISTS held (x)")
db.run("COMMIT")
console.log("locked")
await Bun.sleep(Number(process.argv[3]))
db.close()
