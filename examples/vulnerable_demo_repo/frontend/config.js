// Frontend config with hardcoded token & DOM XSS pattern
export const APP_CONFIG = {
  gitlabToken: "glpat-K9mP2xQ7vL4wN8bZ3yC6",
  renderBanner(htmlStr) {
    document.getElementById("banner").innerHTML = htmlStr;
  }
};
