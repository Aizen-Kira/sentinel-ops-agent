export { COOKIE_NAME, ONE_YEAR_MS } from "@shared/const";

export const getLoginUrl = () => {
  const returnTo = `${window.location.pathname}${window.location.search}`;
  return `/api/oauth/login?returnTo=${encodeURIComponent(returnTo)}`;
};
