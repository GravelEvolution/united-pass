export type AuthorizationPolicy = {
  policyId: string;
  name: string;
  resource: string;
  version: number;
  status: "draft" | "published";
  updatedBy: string;
  updatedAt: string;
};
