import streamlit as st
import pandas as pd
import pydeck as pdk
from curl_proxycheck import update_marker

if 'marker_engine' not in st.session_state:
    st.session_state.marker = update_marker()

if 'ip_df' not in st.session_state:
    st.session_state.ip_df = pd.DataFrame(columns=['lat', 'lon', 'info', 'color'])

@st.fragment(run_every="10s")
def update_map():
    new_ips = st.session_state.marker.fetch()
    
    if new_ips:
        new_rows = []
        for key, res in new_ips.items():
            marker_color = [255, 0, 0] if (res[0] or res[1] or res[2]) else [0, 150, 255]
            
            new_row = {
                'lat': float(res[3]),
                'lon': float(res[4]),
                'info': f"IP: {key} | Proxy: {res[0]} | VPN: {res[1]} | TOR: {res[2]}\n Provider: {res[5]}",
                'color': marker_color
            }
            new_rows.append(new_row)
        if new_rows:
            st.session_state.ip_df = pd.concat([
                st.session_state.ip_df, 
                pd.DataFrame(new_rows)
            ], ignore_index=True)

    layer = pdk.Layer(
        "ScatterplotLayer",
        st.session_state.ip_df,
        get_position="[lon, lat]",
        get_color="color",
        get_radius=80000,
        radius_min_pixels=10, 
        radius_max_pixels=15,
        pickable=True,
    )

    st.pydeck_chart(pdk.Deck(
        map_style=None, 
        initial_view_state=pdk.ViewState(
            latitude=20,
            longitude=0,
            zoom=1,
            pitch=0,
        ),
        layers=[layer],
        tooltip={"text": "{info}"}
    ))

update_map()