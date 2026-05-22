import { currentUser } from "@clerk/nextjs/server";

// missing null check — currentUser() returns null for signed-out users
export default async function Dashboard() {
  const user = await currentUser();
  // crashes for anonymous visitors, leaks stack trace
  return <div>Hello, {user.firstName} ({user.id})</div>;
}
