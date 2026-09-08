export default {
  async fetch(request) {
    const url = new URL(request.url);
    return new Response(
      JSON.stringify({
        status: "ok",
        message: "Worker de test minimal — aurore-instituts-r2",
        path: url.pathname,
        time: new Date().toISOString(),
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json; charset=utf-8" },
      }
    );
  },
};
