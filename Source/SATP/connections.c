#include "connections.h"
#include "satpcommon.h"
#include "memutils.h"

/** \cond */
typedef struct satp_connection_set
{
	satp_connection_state* conset;
	bool* active;
	size_t maximum;
	size_t length;
} satp_connection_set;

static satp_connection_set m_connection_set;
/** \endcond */

bool satp_connections_active(size_t index)
{
	bool res;

	res = false;

	if (index < m_connection_set.length)
	{
		res = m_connection_set.active[index];
	}

	return res;
}

satp_connection_state* satp_connections_add(void)
{
	satp_connection_state* cns;

	cns = NULL;

	if ((m_connection_set.length + 1) <= m_connection_set.maximum)
	{
		m_connection_set.conset = qsc_memutils_realloc(m_connection_set.conset, (m_connection_set.length + 1) * sizeof(satp_connection_state));
		m_connection_set.active = qsc_memutils_realloc(m_connection_set.active, (m_connection_set.length + 1) * sizeof(bool));

		if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
		{
			qsc_memutils_clear(&m_connection_set.conset[m_connection_set.length], sizeof(satp_connection_state));
			m_connection_set.conset[m_connection_set.length].cid = (uint32_t)m_connection_set.length;
			m_connection_set.active[m_connection_set.length] = true;
			cns = &m_connection_set.conset[m_connection_set.length];
			++m_connection_set.length;
		}
	}

	return cns;
}

size_t satp_connections_available(void)
{
	size_t count;

	count = 0;

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			++count;
		}
	}

	return count;
}

void satp_connections_clear(void)
{
	qsc_memutils_clear(m_connection_set.conset, sizeof(satp_connection_state) * m_connection_set.length);

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		m_connection_set.active[i] = false;
		m_connection_set.conset[i].cid = (uint32_t)i;
	}
}

void satp_connections_dispose(void)
{
	if (m_connection_set.conset != NULL)
	{
		satp_connections_clear();

		if (m_connection_set.conset != NULL)
		{
			qsc_memutils_alloc_free(m_connection_set.conset);
			m_connection_set.conset = NULL;
		}
	}

	if (m_connection_set.active != NULL)
	{
		qsc_memutils_alloc_free(m_connection_set.active);
		m_connection_set.active = NULL;
	}

	m_connection_set.length = 0;
	m_connection_set.maximum = 0;
}

satp_connection_state* satp_connections_index(size_t index)
{
	satp_connection_state* res;

	res = NULL;

	if (index < m_connection_set.length)
	{
		res = &m_connection_set.conset[index];
	}

	return res;
}

bool satp_connections_full(void)
{
	bool res;

	res = true;

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			res = false;
			break;
		}
	}

	return res;
}

satp_connection_state* satp_connections_get(uint32_t cid)
{
	satp_connection_state* res;

	res = NULL;

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
			res = &m_connection_set.conset[i];
		}
	}

	return res;
}

void satp_connections_initialize(size_t count, size_t maximum)
{
	assert(count != 0);
	assert(maximum != 0);
	assert(count <= maximum);

	if (count != 0 && maximum != 0 && count <= maximum)
	{
		m_connection_set.length = count;
		m_connection_set.maximum = maximum;
		m_connection_set.conset = (satp_connection_state*)qsc_memutils_malloc(sizeof(satp_connection_state) * m_connection_set.length);
		m_connection_set.active = (bool*)qsc_memutils_malloc(sizeof(bool) * m_connection_set.length);

		if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
		{
			qsc_memutils_clear(m_connection_set.conset, sizeof(satp_connection_state) * m_connection_set.length);

			for (size_t i = 0; i < count; ++i)
			{
				m_connection_set.conset[i].cid = (uint32_t)i;
				m_connection_set.active[i] = false;
			}
		}
	}
}

satp_connection_state* satp_connections_next()
{
	satp_connection_state* res;

	res = NULL;

	if (satp_connections_full() == false)
	{
		for (size_t i = 0; i < m_connection_set.length; ++i)
		{
			if (m_connection_set.active[i] == false)
			{
				res = &m_connection_set.conset[i];
				m_connection_set.active[i] = true;
				break;
			}
		}
	}
	else
	{
		res = satp_connections_add();
	}

	return res;
}

void satp_connections_reset(uint32_t cid)
{
	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
			qsc_memutils_clear(&m_connection_set.conset[i], sizeof(satp_connection_state));
			m_connection_set.conset[i].cid = (uint32_t)i;
			m_connection_set.active[i] = false;
			break;
		}
	}
}

size_t satp_connections_size(void)
{
	return m_connection_set.length;
}

#if defined(SATP_DEBUG_MODE)
void satp_connections_self_test(void)
{
	satp_connection_state* xn[20] = { 0 };
	size_t cnt;
	bool full;

	satp_connections_initialize(1, 10); /* init with 1 */

	for (size_t i = 1; i < 10; ++i)
	{
		xn[i] = satp_connections_next(); /* init next 9 */
	}

	cnt = satp_connections_available(); /* expected 0 */
	full = satp_connections_full(); /* expected true */

	satp_connections_reset(1); /* release 5 */
	satp_connections_reset(3);
	satp_connections_reset(5);
	satp_connections_reset(7);
	satp_connections_reset(9);

	full = satp_connections_full(); /* expected false */

	xn[11] = satp_connections_next(); /* reclaim 5 */
	xn[12] = satp_connections_next();
	xn[13] = satp_connections_next();
	xn[14] = satp_connections_next();
	xn[15] = satp_connections_next();

	full = satp_connections_full(); /* expected true */

	xn[16] = satp_connections_next(); /* should exceed max */

	cnt = satp_connections_size(); /* expected 10 */

	satp_connections_clear();
	satp_connections_dispose();
}
#endif