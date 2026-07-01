import { ResourceContextProvider } from "ra-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { commands } from "vitest/browser";
import { render } from "vitest-browser-react";

import { buildContact, StoryWrapper } from "@/test/StoryWrapper";
import type { Task as TaskRecord } from "../types";
import { Task } from "./Task";

describe("Task", () => {
  let originalTimezone: string;

  beforeEach(async () => {
    originalTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    await commands.setTimezone("UTC");
  });

  afterEach(async () => {
    await commands.setTimezone(originalTimezone);
  });

  it("displays the start date when a task has one", async () => {
    const task: TaskRecord = {
      contact_id: 1,
      due_date: "2026-07-05T17:00:00.000Z",
      id: 1,
      sales_id: 0,
      start_date: "2026-07-02T09:00:00.000Z",
      text: "Draft campaign brief",
      type: "meeting",
    };

    const screen = await render(
      <StoryWrapper
        data={{
          contacts: [buildContact({ id: 1 })],
          tasks: [task],
        }}
      >
        <ResourceContextProvider value="tasks">
          <Task task={task} />
        </ResourceContextProvider>
      </StoryWrapper>,
    );

    await expect.element(screen.getByText(/starts/i)).toBeInTheDocument();
    await expect.element(screen.getByText(/7\/2\/2026/)).toBeInTheDocument();
  });
});
