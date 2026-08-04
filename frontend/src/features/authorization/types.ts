export type ConsentRequest = {
  requestId: string;
  applicationName: string;
  applicationDescription: string;
  applicationOwner: string;
  redirectHost: string;
  scopes: Array<{
    scope: string;
    label: string;
    description: string;
  }>;
};
