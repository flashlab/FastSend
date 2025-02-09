export default oauthLinuxdoEventHandler({
    async onSuccess(event, { user }) {
      await setUserSession(event, {
        user: {
          id: user.id,
          username: user.username,
          name: user.name,
          avatar: user.avatar_url,
          level: user.trust_level,
          active: user.active,
        },
      })
      return sendRedirect(event, '/')
    },
    // Optional, will return a json error and 401 status code by default
    onError(event, error) {
      console.error('linux.do OAuth error:', error)
      return sendRedirect(event, '/')
    },
  })