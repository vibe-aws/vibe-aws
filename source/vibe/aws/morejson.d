module vibe.aws.morejson;

import vibe.data.json;

struct JsonArrayRange
{
    Json m_source;
    uint m_index;

    this(Json source)
    {
        m_source = source;
        m_index = 0;
    }

    @property bool empty()
    {
        return m_index >= m_source.length;
    }

    @property Json front()
    {
        return m_source[m_index];
    }

    void popFront()
    {
        m_index++;
    }
}

JsonArrayRange arrayIterator(Json json)
{
    return JsonArrayRange(json);
}

