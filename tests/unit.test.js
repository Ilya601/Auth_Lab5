import { describe, expect, it } from "vitest";
import { verifyPassword } from "../db/userRepository";

describe("unit", () => {
  it("should verify password", async () => {
    const password = "password";
    const passwordHash = await verifyPassword(password, password);
    expect(passwordHash).toBeDefined();
  });
});
