export type OAuthApplication = {
  applicationId: string;
  name: string;
  clientType: "public" | "confidential";
  ownerName: string;
  status: "active" | "disabled";
  redirectUriCount: number;
  updatedAt: string;
};
