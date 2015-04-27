#ifndef IOREMAP_ELLIPTICS_COMMON_HPP
#define IOREMAP_ELLIPTICS_COMMON_HPP

class dnet_pthread_mutex
{
public:
	dnet_pthread_mutex(pthread_mutex_t &mutex) : m_mutex(mutex)
	{
	}

	void lock()
	{
		pthread_mutex_lock(&m_mutex);
	}

	void unlock()
	{
		pthread_mutex_unlock(&m_mutex);
	}
private:
	pthread_mutex_t &m_mutex;
};

class dnet_pthread_lock_guard
{
public:
	dnet_pthread_lock_guard(pthread_mutex_t &mutex) : m_mutex(mutex), m_lock_guard(m_mutex)
	{
	}

private:
	dnet_pthread_mutex m_mutex;
	std::lock_guard<dnet_pthread_mutex> m_lock_guard;
};

struct free_destroyer
{
	void operator() (void *buffer)
	{
		free(buffer);
	}
};

template <typename Class, typename Method, typename... Args>
inline static int safe_call(Class *obj, Method method, Args &&...args)
{
	try {
		if (obj)
			return (obj->*method)(std::forward<Args>(args)...);
		return 0;
	} catch (std::bad_alloc &) {
		return -ENOMEM;
	} catch (...) {
		return -EINVAL;
	}
}

#endif // IOREMAP_ELLIPTICS_COMMON_HPP
