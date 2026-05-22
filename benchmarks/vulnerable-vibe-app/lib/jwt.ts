import jwt from "jsonwebtoken";

export function issueToken(userId: string) {
  return jwt.sign({ sub: userId }, "changeme");
}

export const STRIPE_KEY = "sk-live-aaaaaaaaaaaaaaaaaaaaaaaa";
