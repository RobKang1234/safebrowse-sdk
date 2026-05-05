import type { TargetPathClass, TaskPurposeClass, TaskSession } from "./types.js";

export const AUTO_ALLOW_PATH_CLASSES: TargetPathClass[] = ["content_read", "docs_navigation"];
export const APPROVAL_REQUIRED_PATH_CLASSES: TargetPathClass[] = [
  "account_settings",
  "admin",
  "export",
  "finalize",
  "authorize",
  "billing",
  "payment",
  "connector_setup",
  "reconciliation"
];
export const DENY_PATH_CLASSES: TargetPathClass[] = [
  "logout",
  "delete",
  "destructive_action",
  "credential_reset"
];

function includesAny(value: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(value));
}

export function inferTaskPurposeClass(
  userGoal: string,
  allowedPathClasses?: TargetPathClass[]
): TaskPurposeClass {
  const combined = `${userGoal} ${(allowedPathClasses ?? []).join(" ")}`.toLowerCase();
  if (includesAny(combined, [/connector/, /oauth/, /integrat/])) {
    return "connector_setup";
  }
  if (includesAny(combined, [/reconcil/, /ledger/, /audit/])) {
    return "reconciliation_review";
  }
  if (includesAny(combined, [/payment/, /billing/, /invoice/])) {
    return "payment";
  }
  if (includesAny(combined, [/admin/, /setting/, /profile/])) {
    return "account_settings";
  }
  if (includesAny(combined, [/docs/, /documentation/, /tutorial/, /reference/, /manual/])) {
    return "docs_navigation";
  }
  return "content_read";
}

export function classifyTargetPathClass(input: {
  targetUrl?: string;
  displayText?: string;
  selector?: string;
}): TargetPathClass {
  const combined = `${input.targetUrl ?? ""} ${input.displayText ?? ""} ${input.selector ?? ""}`.toLowerCase();

  if (includesAny(combined, [/\blog[\s\-_]?out\b/, /\bsign[\s\-_]?out\b/])) {
    return "logout";
  }
  if (includesAny(combined, [/\bcredential\b/, /\bpassword\b/, /reset/])) {
    return "credential_reset";
  }
  if (includesAny(combined, [/\bdelete\b/, /\bremove\b/, /\bdestroy\b/])) {
    return "delete";
  }
  if (includesAny(combined, [/\badmin\b/, /\/admin\b/, /\badministrator\b/])) {
    return "admin";
  }
  if (includesAny(combined, [/\baccount\b/, /\bsettings\b/, /\bprofile\b/])) {
    return "account_settings";
  }
  if (includesAny(combined, [/\bexport\b/, /\bdownload\b/, /ledger/, /csv/, /report/])) {
    return "export";
  }
  if (includesAny(combined, [/\bfinalize\b/, /\bconfirm\b/, /\bcomplete\b/, /\bsubmit\b/])) {
    return "finalize";
  }
  if (includesAny(combined, [/\bconnector\b/, /\boauth\b/, /\bintegration\b/, /\bauthorize\b/, /\bconsent\b/])) {
    return combined.includes("connector") || combined.includes("oauth")
      ? "connector_setup"
      : "authorize";
  }
  if (includesAny(combined, [/\bbilling\b/, /\binvoice\b/])) {
    return "billing";
  }
  if (includesAny(combined, [/\bpayment\b/, /\bcheckout\b/, /\bpay\b/])) {
    return "payment";
  }
  if (includesAny(combined, [/\breconcil/, /internal\/reconciliation/, /\bledger\b/])) {
    return "reconciliation";
  }
  if (includesAny(combined, [/\bdocs?\b/, /\btutorial\b/, /\bguide\b/, /\bmanual\b/, /\breference\b/, /python\.org/])) {
    return "docs_navigation";
  }
  if (input.targetUrl) {
    return "content_read";
  }
  return "workflow_continue";
}

function purposeDefaultAllowedPathClasses(taskPurposeClass: TaskPurposeClass): TargetPathClass[] {
  switch (taskPurposeClass) {
    case "docs_navigation":
      return ["docs_navigation", "content_read"];
    case "workflow_continue":
      return ["workflow_continue", "content_read"];
    case "reconciliation_review":
      return ["reconciliation_review", "reconciliation", "content_read"];
    case "connector_setup":
      return ["connector_setup", "content_read"];
    case "account_settings":
      return ["account_settings", "content_read"];
    case "admin":
      return ["admin", "content_read"];
    case "export":
      return ["export", "content_read"];
    case "finalize":
      return ["finalize", "content_read"];
    case "authorize":
      return ["authorize", "content_read"];
    case "billing":
      return ["billing", "content_read"];
    case "payment":
      return ["payment", "content_read"];
    case "content_read":
    default:
      return ["content_read", "docs_navigation"];
  }
}

export function allowedPathClassesForSession(session: Pick<TaskSession, "taskPurposeClass" | "allowedPathClasses" | "userGoal">): TargetPathClass[] {
  const inferred = session.taskPurposeClass ?? inferTaskPurposeClass(session.userGoal, session.allowedPathClasses);
  return [...new Set([...(session.allowedPathClasses ?? []), ...purposeDefaultAllowedPathClasses(inferred)])];
}

export function approvalRequiredPathClassesForSession(
  session: Pick<TaskSession, "approvalRequiredPathClasses">
): TargetPathClass[] {
  return [...new Set([...(session.approvalRequiredPathClasses ?? []), ...APPROVAL_REQUIRED_PATH_CLASSES])];
}

export function pathClassDenied(pathClass: TargetPathClass): boolean {
  return DENY_PATH_CLASSES.includes(pathClass);
}

export function pathClassAllowedForSession(
  session: Pick<TaskSession, "taskPurposeClass" | "allowedPathClasses" | "userGoal">,
  pathClass: TargetPathClass
): boolean {
  return AUTO_ALLOW_PATH_CLASSES.includes(pathClass) || allowedPathClassesForSession(session).includes(pathClass);
}

export function pathClassRequiresApprovalForSession(
  session: Pick<TaskSession, "approvalRequiredPathClasses">,
  pathClass: TargetPathClass
): boolean {
  return approvalRequiredPathClassesForSession(session).includes(pathClass);
}
